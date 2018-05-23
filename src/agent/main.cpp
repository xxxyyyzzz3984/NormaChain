#include "agent.h"

int main() {
    Agent agent = Agent("/home/xyh3984/CC++Projects/NormaChain/agent_storage/agent_info",
            "/home/xyh3984/CC++Projects/NormaChain/agent_storage/Contract_Chain");
    agent.serve();
//    agent.test();
    return 0;
}
