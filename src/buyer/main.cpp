#include "buyer.h"

int main () {

    Buyer buyer = Buyer();
    buyer.Load_Info_File("../buyer_storage/buyer_info",
                         "../buyer_storage/seller_list",
                         "../buyer_storage/approver_list");
    const clock_t begin_time = clock();
    int currentClock = 0;
    for(int i = 0; i < 40; i++) {
        buyer.Transact(0, "fries", "test", 0);
        currentClock += clock();
//        const clock_t begin_time = clock();
        //buyer.Transact(0, "fries", "test", 0);
//        std::cout << "The transaction time is " << float( clock () - begin_time ) /  CLOCKS_PER_SEC << std::endl;
    }
    std::cout << "The transaction time is " << float( currentClock - begin_time ) /  CLOCKS_PER_SEC << std::endl;
}
