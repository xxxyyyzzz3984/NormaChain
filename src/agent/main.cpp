#include "agent.h"

int main() {
    Agent agent = Agent("../agent_storage/agent_info",
            "../agent_storage/Contract_Chain");
    agent.serve();
//    agent.test();
    return 0;
}
