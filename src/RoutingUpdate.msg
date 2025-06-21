message RoutingUpdate {
    string senderId;
    string destination;
    string nextHop;
    int cost;
    long sequenceNumber;
    string hmac;  // Will store hash value (SHA1, SHA256, or SHA3)
}
