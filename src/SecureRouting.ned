package src;

network SecureRouting {
    parameters:
        int numRouters = default(5);
        int numMalicious = default(1);
        string topology = default("ring");
        double updateInterval @unit("s") = default(1s);
        @display("bgb=640,480");
        
    submodules:
        router[numRouters]: Router {
            routerId = "R" + string(index);
            isMalicious = index < parent.numMalicious;
            updateInterval = parent.updateInterval;
            @display("p=100+100*index,100");
        }
    
    connections allowunconnected:
        // Full mesh topology
        for i=0..numRouters-1, for j=i+1..numRouters-1, if (topology == "full") {
            router[i].port++ <--> { delay = 0.1ms; } <--> router[j].port++;
        }
        
        // Ring topology
        for i=0..numRouters-1, if (topology == "ring") {
            router[i].port++ <--> { delay = 0.1ms; @display("ls=green,2"); } <--> router[(i+1) % numRouters].port++;
        }
        
        // Line topology
        for i=0..numRouters-2, if (topology == "line") {
            router[i].port++ <--> { delay = 0.1ms; } <--> router[i+1].port++;
        }
}