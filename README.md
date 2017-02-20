# Project 6 - Globitek Authentication and Login Throttling

Time spent: **9** hours spent in total

## User Stories

The following **required** functionality is completed:

**(all required stories completed)**

- [x] On the existing pages "public/staff/users/new.php" and "public/staff/users/edit.php", a user sees the appropriate forms
- [x] For both users/new.php and users/edit.php, submitting the form performs data validations
- [x] If all validations on the user data pass, encrypt and store passwords
- [x] Use PHP's password_verify() function to test the entered password against the password stored in users.hashed_password for the username provided and Ensure the login page does not display content which would create a User Enumeration weakness
- [x] Implement login throttling
- [x] Reset failed logins after a successful login
- [x] Watch out for SQLI Injection and Cross-Site Scripting vulnerabilities

The following advanced user stories are optional:

**(all optional stories completed)**

- [x] Bonus 1: Identify the User Enumeration weakness and write a short description of how the code could be improved
  - [x] **(see Notes section)**
- [x] Bonus 2: A blank password will still allow updating other user values and not touch the existing password, but providing a password will validate and update the password too
- [x] Bonus 3: Use the options to set the bcrypt "cost" parameter to 11
  - [x] **(see Notes section)**
- [x] Bonus 4: On "public/staff/users/edit.php", add a new text field for "Previous password". When the form is submitted, validate that the correct password has been provided before allowing the password to be updated
- [x] Advanced 1: Implement `password_hash()` and `password_verify()` same functions yourself using the PHP function crypt() and the bcrypt hash algorithm. Name your versions `my_password_hash()` and `my_password_verify()` and include them in "private/auth_functions.php"
- [x] Advanced 2: Write a PHP function in "private/auth_functions.php" called `generate_strong_password()` which will generate a random strong password containing the number of characters specified be a function argument


## Video Walkthrough

Here's a walkthrough of implemented user stories:

<img src='http://i.imgur.com/iQcdNxJ.gif' title='Video Walkthrough' width='' alt='Video Walkthrough' />

GIF created with [LiceCap](http://www.cockos.com/licecap/).

## Notes

* **Bonus Objective 1:** The subtle User Enumeration weakness with the login pages comes from the username remains when a user exist. This gives hacker information on whether a certain username exist or not and they can attack that particular user based on this information.
* **Bonus Objective 3:** We can still login after changing the bcrypt's cost parameter because `password_verify()` looks at the at the beginning of the hashed password (e.g. $2y$10$salt) to detect which encryption algorithm and the options (such as cost) to use. In that case, we can see that const is 10.
* To complete bonus objective 2 and 4 I ignore previous password if the user is inserting a new user. Otherwise, when the user is editing, I get the previous password and compare. If password is not set, I ignore previous password all together and do not perform the quary. 

## License

    Copyright [2017] [Tianhao Qiu]

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
