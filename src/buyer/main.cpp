#include "buyer.h"

int main () {
    Buyer buyer = Buyer();
    buyer.Load_Info_File("/home/xyh3984/CC++Projects/NormaChain/buyer_storage/buyer_info",
                         "/home/xyh3984/CC++Projects/NormaChain/buyer_storage/seller_list");
    buyer.Transact(0, "fries", "test");
}
