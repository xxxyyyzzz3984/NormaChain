#include "approver/approver.h"

int main(int argc, char** argv) {
    Approver approver = Approver(argv[1],
                                 "../approver_storage/approver_list",
             "../approver_storage/agent_info");
    approver.serve();
    return 0;
}
