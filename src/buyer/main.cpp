#include "buyer.h"

int main () {

    Buyer buyer = Buyer();
    buyer.Load_Info_File("/home/xyh3984/CC++Projects/NormaChain/buyer_storage/buyer_info",
                         "/home/xyh3984/CC++Projects/NormaChain/buyer_storage/seller_list",
                         "/home/xyh3984/CC++Projects/NormaChain/buyer_storage/approver_list");

    const clock_t begin_time = clock();
    buyer.Transact(0, "fries", "test", 0);
    std::cout << "The transaction time is " << float( clock () - begin_time ) /  CLOCKS_PER_SEC << std::endl;
}
