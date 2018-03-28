FindCryptoPP.cmake
==================

Overview
--------

This module allows to locate the `Crypto++`__ library.

__ CryptoPP_

.. _CryptoPP: http://www.cryptopp.com/


Customizable variables
----------------------

  CRYPTOPP_ROOT_DIR
    Specifies the root directory of Crypto++.

Read-only variables
-------------------

  CRYPTOPP_FOUND
    Indicates whether the library has been found.

  CRYPTOPP_INCLUDE_DIRS
    Specifies the Crypto++ include directory.

  CRYPTOPP_LIBRARIES
    Specifies the Crypto++ libraries that should be passed to
    ``target_link_libararies``.
