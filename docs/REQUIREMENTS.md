# Project Details - Secure ATM

## Programming Problem: ATM Protocol

## Summary

Students will implement an ATM communication protocol. There will be two programs. One program, called `atm`, will allow bank customers to withdraw and deposit money from their account. The other program, called `bank`, will run as a server that keeps track of customer balances.

## Deliverables

You should submit:

- Your implementation, including all your code files and your makefile. Even though we will have access to your git repo (details below), you will submit a "final" version by creating a tag on it.
- A **design document** (PDF) in which you describe your overall system design in sufficient detail for a reader to understand your approach without reading the source code directly. This must include a description of how the protocol runs.

## Security Model

`atm` and `bank` must be implemented such that only a customer with a correct card file can learn or modify the balance of their account, and only in an appropriate way (e.g., they may not withdraw more money than they have). In addition, an `atm` may only communicate with a `bank` if it and the `bank` agree on an auth file, which they use to mutually authenticate. The auth file will be shared between the `bank` and `atm` via a trusted channel unavailable to the attacker, and is used to set up secure communications.

Since the ATM client is communicating with the `bank` server over the network, it is possible that there is a "man in the middle" that can observe and change the messages, or insert new messages. A "man in the middle" attacker can view all traffic transmitted between the `atm` and the `bank`. The "man in the middle" may send messages to either the `atm` or the `bank`.

The source code for `atm` and `bank` will be available to attackers, but not the auth file. The card file may be available in some cases, depending on the kind of attack.

## Requirements

The specification details for each program are given below.

- Bank Server
  - `bank` is a server than simulates a bank, whose job is to keep track of the balance of its customers. It will receive communications from `atm` clients on the specified TCP port. Example interactions with `bank` and the `atm` are given at the bottom of the page.

    ```bash
    bank [-p <port>] [-s <auth-file>]
    ```

    On startup, `bank` will generate a auth file with the specified name. Existing auth files are not valid for new runs of `bank` -- if the specified file already exists, `bank` should exit with return code 255. Once the auth file is written completely, `bank` prints "created" (followed by a newline) to stdout. `bank` will not change the auth file once "created" has been printed.

    If an invalid command-line option is provided, the `bank` program should exit with return value 255.

    After startup, `bank` will wait to receive transaction requests from clients; these transactions and how the `bank` should respond are described in the `atm` specification. After every transaction, `bank` prints a JSON-encoded summary of the transaction to stdout, followed by a newline (this summary is also described in the `atm` spec). `bank` should bind to any host.

    The `bank` program will run and serve requests until it receives a SIGTERM signal, at which point it should exit cleanly. `bank` will continue running no matter what data its connected clients might send; i.e., invalid data from a client should not cause the server to exit and thereby deny access to other clients.

    The `bank` program will not write to any private files to keep state between multiple runs of the program.

  ### Options

  There are two optional parameters. They can appear in any order. Any invocation of the `bank` that does not follow the command-line specification outlined above should result only with the return code of 255 from the `bank`. I.e., invocations with duplicated or non-specified parameters are considered an error.
  - `-p <port>` The port that `bank` should listen on. The default is `3000`.

  - `-s <auth-file>` The name of the auth file. If not supplied, defaults to "`bank.auth`".

* ATM Client
  - `atm` is a client program that simulates an ATM by providing a mechanism for customers to interact with their bank accounts stored on the bank server. `atm` allows customers to create new accounts, deposit money, withdraw funds, and check their balances. In all cases, these functions are achieved via communiations with the bank. `atm` cannot store any state or write to any files except the card-file. The card-file can be viewed as the "pin code" for one's account; there is one card file per account. Card files are created when `atm` is invoked with -n to create a new account; otherwise, card files are only read, and not modified.

    Any invocation of the `atm` which does not follow the four enumerated possibilities above should exit with return code 255 (printing nothing). Noncompliance includes a missing account or mode of operation and duplicated parameters. Note that parameters may be specified in any order.

  ```bash
  atm [-s <auth-file>] [-i <ip-address>] [-p <port>] [-c <card-file>] -a <account> -n <balance>
  atm [-s <auth-file>] [-i <ip-address>] [-p <port>] [-c <card-file>] -a <account> -d <amount>
  atm [-s <auth-file>] [-i <ip-address>] [-p <port>] [-c <card-file>] -a <account> -w <amount>
  atm [-s <auth-file>] [-i <ip-address>] [-p <port>] [-c <card-file>] -a <account> -g
  ```

  ### Required Parameter
  - `-a <account>` The customer's account name. (The format for the account is given below

  ### Optional Parameters
  - `-s <auth-file>` The authentication file that `bank` creates for the `atm`. If `-s` is not specified, the default filename is "`bank.auth`" (in the current working directory). If the specified file cannot be opened or is invalid, the atm exits with a return code of `255`.

  - `-i <ip-address>` The IP address that bank is running on. The default value is "`127.0.0.1`".

  - `-p <port>` The TCP port that bank is listening on. The default is `3000`.

  - `-c <card-file>` The customer's atm card file. The default value is the account name prepended to "`.card`" ("`<account>.card`"). For example, if the account name was `55555`, the default card file is "`55555.card`".

  ### Modes of Operation

  In addition to the account name, an invocation must provide a "mode of operation". Each of the above 4 invocations uses one such mode; these are enumerated below.
  - `-n <balance>` Create a new account with the given balance. The account must be unique (ie, the account must not already exist). The balance must be greater than or equal to `10.00`. The given card file must not already exist. If any of these conditions do not hold, `atm` exits with a return code of 255. On success, both `atm` and `bank` print the account and initial balance to standard output, encoded as JSON. The account name is a JSON string with key "`account`", and the initial balance is a JSON number with key "`initial_balance`" (Example: `{"account":"55555","initial_balance":10.00}`). In addition, `atm` creates the card file for the new account (think of this as like an auto-generated pin).

  - `-d <amount>` Deposit the amount of money specified. The amount must be greater than `0.00`. The specified account must exist, and the card file must be associated with the given account (i.e., it must be the same file produced by `atm` when the account was created). If any of these conditions do not hold, `atm` exits with a return code of `255`. On success, both `atm` and `bank` print the account and deposit amount to standard output, encoded as JSON. The account name is a JSON string with key "`account`", and the deposit amount is a JSON number with key "`deposit`" (Example: `{"account":"55555","deposit":20.00}`).

  - `-w <amount>` Withdraw the amount of money specified. The amount must be greater than `0.00`, and the remaining balance must be nonnegative. The card file must be associated with the specified account (i.e., it must be the same file produced by `atm` when the account was created). The ATM exits with a return code of `255` if any of these conditions are not true. On success, both `atm` and `bank` print the account and withdraw amount to standard output, encoded as JSON. The account name is a JSON string with key "`account`", and the withdraw amount is a JSON number with key "`withdraw`" (Example: `{"account":"55555","withdraw":15.00}`).

  - `-g` Get the current balance of the account. The specified account must exist, and the card file must be associated with the account. Otherwise, `atm` exits with a return code of `255`. On success, both `atm` and `bank` print the account and balance to **stdout**, encoded as JSON. The account name is a JSON string with key "`account`", and the balance is a JSON number with key "`balance`" (Example: `{"account":"55555","balance":43.63}`).

Here are some general requirements that apply to both `atm` and `bank` programs.

### Valid Inputs

Any command-line input that is not valid according to the rules below should result with a return value of 255 from the invoked program and nothing should be output to _stdout_.

- Command line arguments must be [POSIX compliant](http://pubs.opengroup.org/onlinepubs/9699919799/basedefs/V1_chap12.html). and each argument cannot exceed 4096 characters (with additional restrictions below). In particular, this allows command arguments specified as "`-i 4000`" to be provided without the space as "`-i4000`" or with extra spaces as in "`-i 4000`". Arguments may appear in any order. You should not implement `--`, which is optional for POSIX compliance. You should implement guideline 5 (ex. `atm -ga ray` is valid).

* Numeric inputs are positive and provided in decimal without any leading 0's (should match /(0|[1-9][0-9]\*)/). Thus "42" is a valid input number but the octal "052" or hexadecimal "0x2a" are not. Any reference to "number" below refers to this input specification.

* Balances and currency amounts are specified as a number indicating a whole amount and a fractional input separated by a period. The fractional input is in decimal and is always two digits and thus can include a leading 0 (should match /[0-9]{2}/). The interpretation of the fractional amount v is that of having value equal to v/100 of a whole amount (akin to cents and dollars in US currency). Command line input amounts are bounded from 0.00 to 4294967295.99 inclusively but an account may accrue any non-negative balance over multiple transactions.

* File names are restricted to underscores, hyphens, dots, digits, and lowercase alphabetical characters (each character should match /[_\-\.0-9a-z]/). File names are to be between 1 and 127 characters long. The special file names "." and ".." are not allowed.

* Account names are restricted to same characters as file names but they are inclusively between 1 and 122 characters of length, and "." and ".." are valid account names.

* IP addresses are restricted to IPv4 32-bit addresses and are provided on the command line in dotted decimal notation, i.e., four numbers between 0 and 255 separated by periods.

* Ports are specified as **numbers** between 1024 and 65535 inclusively.

### Outputs

- Anything printed to **stderr** will be ignored (e.g., so detailed error messages could be printed there, if desired).

- All JSON output is printed on a single line and is followed by a newline.

- JSON outputs must show numbers (including potentially unbounded account balances) with full precision.

- Newlines are '\n' -- the ASCII character with code decimal 10.

- Both programs should explicitly flush stdout after every line printed.

- Successful exits should return exit code `0`.

### Errors

#### Protocol Error

- If an error is detected in the protocol's communication, `atm` should exit with return code `63`, while `bank` should print "`protocol_error`" to stdout (followed by a newline) and roll back (i.e., undo any changes made by) the current transaction.

- A timeout occurs if the other program does not respond within 10 seconds. If the `atm` observes the timeout, it should exit with return code `63`, while if the `bank` observes it, it should print "`protocol_error`" to stdout (followed by a newline) and rollback the current transaction. The non-observing party need not do anything in particular.

- If `atm` cannot connect to the `bank`, it should exit with return code `63`.

### Other Errors

- All other errors, specified throughout this document or unrecoverable errors not explicitly discussed, should prompt the program to exit with return code `255`.

## Changes and Updates

There will inevitably be changes to the specification during the semester as unclear assumptions and mistakes on our part are uncovered. We apologize in advance!

All changes will be summarized at the top of this page.

## Submission

Each group should initialize a git repository on github and share it with us. **You MUST NOT make your repository public; doing so will be treated as a violation of honor code.**

Create a directory named `build` in the top-level directory of this repository and commit your code into that folder. (Beware making your repository public, or others might be able to see it!)

To score a submission, we will first invoke `make` in the `build` directory of your submission. The only requirement on `make` is that it must function without internet connectivity, and that it must return within a few minutes. Moreover, it must be the case that your software is actually built, through initiation of `make`, from source (not including libraries you might use). Submitting binaries (only) is not acceptable.

Once make finishes, `atm` and `bank` should be executable files within the `build` directory. We will invoke them with a variety of options and measure their responses. The executables must be able to be run from any working directory. If your executables are bash scripts, you may find the following [resource](http://stackoverflow.com/questions/59895/can-a-bash-script-tell-what-directory-its-stored-in) helpful.

## Examples

Here is an example of how to use `atm` and `bank`. First, do some setup and run `bank`.

```bash
$ mkdir bankdir; mv bank bankdir/; cd bankdir/; ./bank -s bank.auth &; cd ..
created
```

Now set up the `atm`.

```bash
$ mkdir atmdir; cp bankdir/bank.auth atmdir/; mv atm atmdir/; cd atmdir
```

Create an account 'bob' with balance Rs. 1000.00 (There are two outputs because one is from the bank which is running in the same shell).

```bash
$ ./atm -s bank.auth -c bob.card -a bob -n 1000.00
{"account":"bob","initial_balance":1000}
{"account":"bob","initial_balance":1000}
```

Deposit Rs. 100.

```bash
$ ./atm -c bob.card -a bob -d 100.00
{"account":"bob","deposit":100}
{"account":"bob","deposit":100}
```

Withdraw Rs. 63.10.

```bash
$ ./atm -c bob.card -a bob -w 63.10
{"account":"bob","withdraw":63.1}
{"account":"bob","withdraw":63.1}
```

Attempt to withdraw Rs. 2000, which fails since 'bob' does not have a sufficient balance.

```bash
$ ./atm -c bob.card -a bob -w 2000.00
$ echo $?
255
```

Attempt to create another account 'bob', which fails since the account 'bob' already exists.

```bash
$ ./atm -a bob -n 2000.00
$ echo $?
255
```

Create an account 'alice' with balance Rs. 1500.

```bash
$ ./atm -a alice -n 1500.00
{"account":"alice","initial_balance":1500}
{"account":"alice","initial_balance":1500}
Bob attempts to access alice's balance with his card, which fails.
```

```bash
$ ./atm -a alice -c bob.card -g
$ echo $?
255
```

### A note on concurrent transactions

In principle, the bank could accept transaction requests from multiple ATMs concurrently, if it chose to---there is no requirement that it must. If it does, the order that these transactions take effect is non-deterministic, but atomic. For example, if ATM #1 requested a deposit of Rs. 50 to Bob's account and ATM #2 requested a withdrawal of Rs. 25 from Bob's account, those two requests could take effect in either order, but when they complete Bob should always be Rs. 25 richer. Note that an atomic transaction includes both changes/accesses to the balance and the corresponding I/O. As such, the order of any printed statements about events must match the order the events actually took place.

Tests are sequences of synchronous ATM commands. During the break-it round, tests also involve a "man in the middle" (MITM) which could introduce concurrency (see the description of the attacker model), but the MITM will never have direct access to the card file or auth file, so its ability to initiate concurrent transactions is more limited than the ATM.
