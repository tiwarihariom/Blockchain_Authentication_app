# Blockchain-based Authentication

This project shows how the use of Blockchain allows to create a Blockchain-based authentication where the user's login data hash is stored in a smart contract.

---

## What authentication is

Authentication is a security process through which a proof of identity or ownership is required. It allows a user owning an account login credentials to login to their account while denying access to others. In most cases, the user's login information are stored in a server, therefore the authentication process is an interaction between the user and a server, and since this can give access to sensitive information, the server in which login credential are stored must be secured. A blockchain-based authentication (BBA) is proposed in order to lower malicious access and increase security to the authentication process.


```solidity
//===================
// Authentication.sol
//===================


pragma solidity 0.8.6;


contract Authentication {
    uint256 public nbOfUsers;

    struct User {
        string signatureHash;
        address userAddress;
    }

    mapping(address => User) private user;

    constructor() {
        nbOfUsers = 0;
    }

    function register(string memory _hash) public {
        require(
            user[msg.sender].userAddress ==
                address(0x0000000000000000000000000000000000000000),
            "already registered"
        );

        user[msg.sender].signatureHash = _hash;
        user[msg.sender].userAddress = msg.sender;
        nbOfUsers++;
    }

    function getSignatureHash() public view returns (string memory) {
        require(msg.sender == user[msg.sender].userAddress, "Not allowed");

        return user[msg.sender].signatureHash;
    }

    function getUserAddress() public view returns (address) {
        return user[msg.sender].userAddress;
    }
}
```

---

```javascript
//==================
// AuthValidation.js
//==================


import SignData from "./SignData";

const AuthValidation = async (
  username,
  accountAddress,
  password,
  digiCode,
  web3,
  contract
) => {
  let userAddress = await contract.methods
    .getUserAddress()
    .call({ from: accountAddress });

  if (userAddress.toLowerCase() !== accountAddress.toLowerCase()) {
    return false;
  } else {
    let signedData = await SignData(username, accountAddress, web3);
    let passwordDigiCodeHash = await web3.eth.accounts.hashMessage(
      password + digiCode
    );

    let hash = await web3.eth.accounts.hashMessage(
      signedData + passwordDigiCodeHash
    );

    // get hash from the contract
    let hashFromContract = await contract.methods
      .getSignatureHash()
      .call({ from: accountAddress });

    if (hash === hashFromContract) {
      return true;
    } else {
      return false;
    }
  }
};

export default AuthValidation;
```

---

```javascript
//======================
// AuthenticationHash.js
//======================


import SignData from "./SignData";

const AuthenticationHash = async (
  username,
  accountAddress,
  password,
  digiCode,
  web3
) => {
  let signedMessage = await SignData(username, accountAddress, web3);
  let passwordDigiCodeHash = await web3.eth.accounts.hashMessage(
    password + digiCode
  );

  return await web3.eth.accounts.hashMessage(
    signedMessage + passwordDigiCodeHash
  );
};

export default AuthenticationHash;
```

---

```javascript
//============
// SignData.js
//============

/*
 * @dev returns the unique hash based on the username and ethereum address
 */

const SignData = async (username, accountAddress, web3) => {
  let signedData;

  await web3.eth.personal.sign(username, accountAddress, (err, signature) => {
    if (err) {
      signedData = err;
    } else {
      signedData = web3.eth.accounts.hashMessage(signature);
    }
  });

  return signedData;
};

export default SignData;
```

---

## Diagram

The following diagram shows all steps to generate the user's login data hash from the username, the password, the 6 digit code and the ethereum address. To register the user must fill a form to provide the username, the password and the 6 digit code, the ethereum address is retrieved directly from the wallet. This address is associated to the username to generate a signature via the web3 function sign, the generated signature is hashed (hash1). The password is associated with the 6 digit code to generate another hash (hash2). The two hashes are combined to generated the final hash that is stored in the smart contract. To login, the user must be connected to the Blockchain with the same address used during registration, and fill the login form with right username, password and the 6 digit code. The back-end code then generates the hash with this login information and compares it with the hash that was stored in the smart contract by the ethereum address which request the login, if the two hashes match, then the user is authorized to login, if not, the access is denied.

![alt text](https://github.com/Edoumou/blockchain-based-authentication/blob/main/client/src/img/pdf/diagram.png "BBA diagram")

---


