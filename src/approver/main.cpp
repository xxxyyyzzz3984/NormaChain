#include "approver/approver.h"

int main(int argc, char** argv) {
    Approver approver = Approver(argv[1],
                                 "/home/xyh3984/CC++Projects/NormaChain/approver_storage/approver_list",
             "/home/xyh3984/CC++Projects/NormaChain/approver_storage/agent_info");
    approver.serve();
    return 0;
}