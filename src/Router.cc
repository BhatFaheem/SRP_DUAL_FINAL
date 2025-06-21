#include "Router.h"
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <iomanip>
#include <sstream>

Define_Module(Router);

std::string Router::computeSHA1(const std::string &senderId,
                                const std::string &destination,
                                const std::string &nextHop,
                                int cost,
                                long sequenceNumber) {
    // Create the data string to be authenticated with secret key
    std::string data = SECRET_KEY + senderId + ";" + destination + ";" + nextHop + ";" +
                      std::to_string(cost) + ";" + std::to_string(sequenceNumber);

    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA1((unsigned char*)data.c_str(), data.size(), hash);

    // Convert to hex string
    std::ostringstream ss;
    for(int i = 0; i < SHA_DIGEST_LENGTH; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }

    std::string hash_hex = ss.str();
    EV << "SHA1 computed for data: " << data << " -> " << hash_hex.substr(0, 16) << "..." << endl;

    return hash_hex;
}

std::string Router::computeSHA256(const std::string &senderId,
                                 const std::string &destination,
                                 const std::string &nextHop,
                                 int cost,
                                 long sequenceNumber) {
    // Create the data string to be authenticated with secret key
    std::string data = SECRET_KEY + senderId + ";" + destination + ";" + nextHop + ";" +
                      std::to_string(cost) + ";" + std::to_string(sequenceNumber);

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)data.c_str(), data.size(), hash);

    // Convert to hex string
    std::ostringstream ss;
    for(int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }

    std::string hash_hex = ss.str();
    EV << "SHA256 computed for data: " << data << " -> " << hash_hex.substr(0, 16) << "..." << endl;

    return hash_hex;
}

std::string Router::computeSHA3_256(const std::string &senderId,
                                   const std::string &destination,
                                   const std::string &nextHop,
                                   int cost,
                                   long sequenceNumber) {
    // Create the data string to be authenticated with secret key
    std::string data = SECRET_KEY + senderId + ";" + destination + ";" + nextHop + ";" +
                      std::to_string(cost) + ";" + std::to_string(sequenceNumber);

    const EVP_MD *algo = EVP_sha3_256();
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int len = 0;

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        EV << "EVP context creation failed!" << endl;
        return "SHA3_ERROR";
    }

    if (EVP_DigestInit_ex(ctx, algo, NULL) != 1) {
        EV << "SHA3 initialization failed!" << endl;
        EVP_MD_CTX_free(ctx);
        return "SHA3_ERROR";
    }

    if (EVP_DigestUpdate(ctx, data.data(), data.size()) != 1) {
        EV << "SHA3 update failed!" << endl;
        EVP_MD_CTX_free(ctx);
        return "SHA3_ERROR";
    }

    if (EVP_DigestFinal_ex(ctx, digest, &len) != 1) {
        EV << "SHA3 finalization failed!" << endl;
        EVP_MD_CTX_free(ctx);
        return "SHA3_ERROR";
    }

    EVP_MD_CTX_free(ctx);

    // Convert to hex string
    std::ostringstream ss;
    for (unsigned int i = 0; i < len; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)digest[i];
    }

    std::string hash_hex = ss.str();
    EV << "SHA3-256 computed for data: " << data << " -> " << hash_hex.substr(0, 16) << "..." << endl;

    return hash_hex;
}

void Router::initialize() {
    EV << "=== Router " << routerId << " INITIALIZING ===" << endl;
    EV << "Current time: " << simTime() << endl;
    EV << "Gate count: " << gateSize("port") << endl;

    scheduleAt(simTime() + 1.0, new cMessage("TestMessage"));

    // Initialize parameters
    routerId = par("routerId").stdstringValue();
    isMalicious = par("isMalicious");
    updateInterval = par("updateInterval");

    // Initialize state
    sequenceNumber = 0;
    lastChangeTime = simTime();

    // Initialize statistics
    numSentUpdates = numReceivedUpdates = numAuthFailures = numMaliciousUpdatesSent = 0;

    // Add self to routing table
    RouteEntry selfEntry{routerId, 0, sequenceNumber, simTime()};
    routingTable[routerId] = selfEntry;

    // Schedule first update
    updateTimer = new cMessage("updateTimer");
    scheduleAt(simTime() + uniform(0.1, 0.5), updateTimer);

    EV << "Router " << getFullName() << " initialized. ID: " << routerId
       << ", Malicious: " << (isMalicious ? "Yes" : "No") << endl;

    EV << "Router " << routerId << " initialized. Malicious: "
       << (isMalicious ? "YES" : "NO") << ", Secret Key: " << SECRET_KEY << endl;
    EV << "=== Router " << routerId << " INITIALIZATION COMPLETE ===" << endl;
}

void Router::handleMessage(cMessage *msg) {
    if (msg->isSelfMessage() && strcmp(msg->getName(), "TestMessage") == 0) {
        EV << "Test message received at t=" << simTime() << endl;
        delete msg;
        return;
    }

    EV << "Router " << getFullName() << " received message: " << msg->getName() << endl;

    if (msg == updateTimer) {
        sendRoutingUpdate();
        scheduleAt(simTime() + updateInterval, updateTimer);
    }
    else if (auto update = dynamic_cast<RoutingUpdate *>(msg)) {
        numReceivedUpdates++;

        if (!isMalicious) {
            // Compute expected hash for authentication using SHA-256
            std::string expectedHash = computeSHA256(
                update->getSenderId(), update->getDestination(),
                update->getNextHop(), update->getCost(), update->getSequenceNumber()
            );

            std::string receivedHash = std::string(update->getHmac());

            if (receivedHash != expectedHash) {
                EV << "[SECURITY] " << routerId << ": Authentication FAILED for update from "
                   << update->getSenderId() << " to " << update->getDestination()
                   << " (cost: " << update->getCost() << ")" << endl;
                EV << "[SECURITY] Expected: " << expectedHash.substr(0, 16) << "..." << endl;
                EV << "[SECURITY] Received: " << receivedHash.substr(0, 16) << "..." << endl;
                numAuthFailures++;
                delete msg;
                return;
            } else {
                EV << "[SECURITY] " << routerId << ": Authentication PASSED for update from "
                   << update->getSenderId() << " (Hash: " << expectedHash.substr(0, 16) << "...)" << endl;
            }
        } else {
            EV << "[MALICIOUS] " << routerId << ": Malicious router accepting all updates without verification" << endl;
        }

        processRoutingUpdate(update);
        delete msg;
    }
}

void Router::sendRoutingUpdate() {
    EV << "Router " << routerId << " sending update at t=" << simTime() << endl;
    EV << "Routing table size: " << routingTable.size() << endl;

    for (const auto &entry : routingTable) {
        const auto &dest = entry.first;
        const auto &route = entry.second;

        for (int i = 0; i < gateSize("port"); i++) {
            cGate* outGate = gate("port$o", i);
            if (outGate && outGate->isConnected()) {
                auto update = new RoutingUpdate();
                update->setDestination(dest.c_str());
                update->setNextHop(route.nextHop.c_str());
                update->setCost(route.cost);
                update->setSequenceNumber(route.sequenceNumber);
                update->setSenderId(routerId.c_str());

                if (isMalicious) {
                    // Malicious behavior: Send invalid hash
                    std::string invalidHash = "MALICIOUS_HASH_" + std::to_string(numMaliciousUpdatesSent++);
                    update->setHmac(invalidHash.c_str());
                    EV << "[MALICIOUS] " << routerId << ": Sending INVALID HASH: " << invalidHash << endl;
                } else {
                    // Legitimate behavior: Compute proper hash using SHA-256
                    std::string validHash = computeSHA256(
                        routerId, dest, route.nextHop, route.cost, route.sequenceNumber
                    );
                    update->setHmac(validHash.c_str());
                    EV << "[LEGITIMATE] " << routerId << ": Sending valid SHA-256 hash for route to " << dest << endl;
                }

                send(update, "port$o", i);
                numSentUpdates++;
            }
        }
    }

    EV << routerId << ": Sent routing update (" << routingTable.size() << " entries)" << endl;
}

void Router::processRoutingUpdate(RoutingUpdate *update) {
    std::string sender = update->getSenderId();
    std::string dest   = update->getDestination();
    std::string next   = update->getNextHop();
    int cost           = update->getCost();
    long seq           = update->getSequenceNumber();

    int totalCost = cost + 1;
    bool changed = updateRoute(dest, sender, totalCost, seq);
    if (changed) {
        EV << routerId << ": Updated route to " << dest
           << " via " << sender << " (cost: " << totalCost
           << ", seq: " << seq << ")" << endl;
    }
}

bool Router::updateRoute(const std::string &destination,
                         const std::string &nextHop,
                         int cost,
                         long sequenceNumber) {
    auto it = routingTable.find(destination);
    if (it == routingTable.end()) {
        routingTable[destination] = {nextHop, cost, sequenceNumber, simTime()};
        lastChangeTime = simTime();
        return true;
    }

    auto &entry = it->second;
    if (sequenceNumber > entry.sequenceNumber ||
        (sequenceNumber == entry.sequenceNumber && cost < entry.cost)) {
        entry = {nextHop, cost, sequenceNumber, simTime()};
        lastChangeTime = simTime();
        return true;
    }
    return false;
}

void Router::finish() {
    recordScalar("numSentUpdates", numSentUpdates);
    recordScalar("numReceivedUpdates", numReceivedUpdates);
    recordScalar("numAuthFailures", numAuthFailures);
    recordScalar("numMaliciousUpdatesSent", numMaliciousUpdatesSent);
    recordScalar("lastChangeTime", lastChangeTime);
    recordScalar("isMalicious", isMalicious);

    // Security statistics
    double authSuccessRate = numReceivedUpdates > 0 ?
        (double)(numReceivedUpdates - numAuthFailures) / numReceivedUpdates * 100.0 : 100.0;
    recordScalar("authenticationSuccessRate", authSuccessRate);

    EV << "\n===== SECURITY REPORT for " << routerId << " =====\n";
    EV << "Total Updates Received: " << numReceivedUpdates << "\n";
    EV << "Authentication Failures: " << numAuthFailures << "\n";
    EV << "Authentication Success Rate: " << authSuccessRate << "%\n";
    if (isMalicious) {
        EV << "Malicious Updates Sent: " << numMaliciousUpdatesSent << "\n";
    }
    EV << "===============================================\n";

    EV << "\n===== Final Routing Table for " << routerId << " =====\n";
    for (const auto &entry : routingTable) {
        EV << entry.first << "\t" << entry.second.nextHop
           << "\t" << entry.second.cost << "\t"
           << entry.second.sequenceNumber << "\t"
           << entry.second.lastUpdateTime << "\n";
    }
    EV << "=================================\n";

    cancelAndDelete(updateTimer);
}
