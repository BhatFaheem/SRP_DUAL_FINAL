#ifndef __ROUTER_H__
#define __ROUTER_H__

#include <omnetpp.h>
#include <map>
#include <string>
#include <sstream>
#include <iomanip>
#include "RoutingUpdate_m.h"

using namespace omnetpp;

struct RouteEntry {
    std::string nextHop;
    int cost;
    long sequenceNumber;
    simtime_t lastUpdateTime;
};

class Router : public cSimpleModule {
  private:
    // Configuration
    bool isMalicious;
    std::string routerId;
    simtime_t updateInterval;

    // State
    std::map<std::string, RouteEntry> routingTable;
    long sequenceNumber;
    simtime_t lastChangeTime;
    cMessage *updateTimer;

    // Statistics
    int numSentUpdates;
    int numReceivedUpdates;
    int numAuthFailures;
    int numMaliciousUpdatesSent;

    // Security - Use a more complex key for production
    const std::string SECRET_KEY = "SecureRoutingProtocol_FinalYearProject_2024!@#$";

    /**
     * Computes SHA-256 hash for message authentication
     * @param senderId The ID of the router sending the update
     * @param destination The destination router in the routing update
     * @param nextHop The next hop router for this route
     * @param cost The cost/distance of the route
     * @param sequenceNumber The sequence number for freshness
     * @return Hex string representation of SHA-256 hash
     */
    std::string computeSHA256(const std::string &senderId,
                             const std::string &destination,
                             const std::string &nextHop,
                             int cost,
                             long sequenceNumber);

    /**
     * Computes SHA-1 hash for message authentication
     * @param senderId The ID of the router sending the update
     * @param destination The destination router in the routing update
     * @param nextHop The next hop router for this route
     * @param cost The cost/distance of the route
     * @param sequenceNumber The sequence number for freshness
     * @return Hex string representation of SHA-1 hash
     */
    std::string computeSHA1(const std::string &senderId,
                           const std::string &destination,
                           const std::string &nextHop,
                           int cost,
                           long sequenceNumber);

    /**
     * Computes SHA3-256 hash for message authentication
     * @param senderId The ID of the router sending the update
     * @param destination The destination router in the routing update
     * @param nextHop The next hop router for this route
     * @param cost The cost/distance of the route
     * @param sequenceNumber The sequence number for freshness
     * @return Hex string representation of SHA3-256 hash
     */
    std::string computeSHA3_256(const std::string &senderId,
                                const std::string &destination,
                                const std::string &nextHop,
                                int cost,
                                long sequenceNumber);

    // Routing functions
    void sendRoutingUpdate();
    void processRoutingUpdate(RoutingUpdate *update);
    bool updateRoute(const std::string &destination,
                     const std::string &nextHop,
                     int cost,
                     long sequenceNumber);

  protected:
    virtual void initialize() override;
    virtual void handleMessage(cMessage *msg) override;
    virtual void finish() override;
};

#endif
