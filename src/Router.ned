package src;

simple Router {
    parameters:
        string routerId;
        bool isMalicious;
        double updateInterval @unit("s");
        @display("i=block/routing");
        
    gates:
        inout port[] @allowunconnected;  // Dynamic gate array
}