# function-clarity
![image](https://user-images.githubusercontent.com/109651023/189649537-95638785-618f-4c74-93af-2cafedec2f07.png)
FunctionClarity (AKA FC) is an infrastructure solution for serverless functions (running code/image) signing and verification. The solution is combined from cli tool and a cloud specific infrastrucute for validation. The solution is suitable for ci/cd process where a code/image of serverless functions can be signed and uploaded beofre the function is created.

## how it works

![Untitled Diagram(1) drawio (1)](https://user-images.githubusercontent.com/109651023/189673319-5c66fb32-98f5-430c-a01f-4823ab51fc98.png)

* Deploy FC infrastructure (one time operation) which will result in function clarity eco system deployed in the users cloud account
* Using the FC cli, run code/image signing on user's environment - at this phase the code/image signature is uploaded to the cloud.
* deploy serverless function using the signed code/image content from the previous step
* Verifier lambda is trigerred upon create-function/update-function code events and performs the following:
  * fetch the verfied function code
  * analayze the code image/zip
  * check whether its signed by FC and act accordingly:
    * detect - marks the function with the verfication results
    * block - block the function from running in case its not verified
    * notify - send notification to queue.

## Install Fuction Clarity
Fill installation instructions once the distribution is ready
## Quick start
The quick start will be conducted against aws account
We will show how to:
* Init and deploy FC
* Sign and upload code
* create aws function
* Check verfication
  * From the cloud account
  * From FC command line

### Init and deploy FC
The command prompts the user to enter information regarding the installation of FC.
When the command finishes to run FC will be deployed to aws account and a configuration file will be created locally.
```shell
./function-clarity init aws
enter Access Key:
enter Secret Key:
enter region:
enter default bucket (you can leave empty and a bucket with name functionclarity will be created):
select post verification action : (1) for detect; (2) for block; leave empty for no post verification action to perform 
is there existing trail in CloudTrail which you would like to use? (if no, please press enter): 
do you want to work in keyless mode (y/n): n
enter path to custom public key for code signing? (if you want us to generate key pair, please press enter): 
Enter password for private key:
Enter password for private key again:
File cosign.key already exists. Overwrite (y/n)? y

Private key written to cosign.key
Public key written to cosign.pub
deployment finished successfully
```

### Sign code
The command below will sign folder with code and upload it to the user's cloud account

```shell
./function-clarity sign aws code /sample-code-verified-folder

using config file: /Users/shaiembon/.fc
Enter password for private key:
MEYCIQDskDWwLEURdALycGH/ntCRjA5G74yJ/qeSDzHTQSRY8gIhALE6Z5XW/iyjz++rzrdhzskPwfwW2gAMjK1H9lCXOGom
Code uploaded successfully
```
