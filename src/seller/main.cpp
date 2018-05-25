#include "seller.h"

int main() {
    Seller seller = Seller("../seller_storage/seller1_info");
    seller.waitforTransaction();
}
