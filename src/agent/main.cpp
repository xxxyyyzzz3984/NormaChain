#include "agent.h"

int main() {
    Agent* agent = new Agent("../agent_storage/agent_info",
            "../agent_storage/Contract_Chain");
    agent->serve();
    delete(agent);
//    agent.test();
    return 0;
}
