![image](https://user-images.githubusercontent.com/109651023/189649537-95638785-618f-4c74-93af-2cafedec2f07.png)
FunctionClarity is a code integrity solution for serverless functions. It allows users to sign their serverless functions and verify their integrity prior to their execution in their cloud environments. FunctionClarity includes a CLI tool, complemented by a "verification" function deployed in the target cloud account.  The solution is designed for CI/CD insertion, where the serverless function code/images can be signed and uploaded before the function is created in the cloud repository.

This version supports serverless functions on AWS (Lambda functions) only, support for Azure functions and Google functions/cloud-run are part of the near-term roadmap plan.

## How does it work?


![FunctionClarity Diagram](https://user-images.githubusercontent.com/110329574/197707276-10cd650e-a84d-4a9f-a83a-ee60dc2cbf28.png)

* Deploy FunctionClarity – deploy FunctionClarity "validation" function in the target cloud account (a one time operation); this function will scan and verify new functions when created or updated in the target account
* Sign functions  - use FunctionClarity CLI to sign the function code or image in the user’s environment, and then upload it to the target cloud account
* Deploy the serverless function - using the signed function code/image 
* Verify functions -  the FunctionClarity verifier function is triggered when user functions are created or updated in case they meet the filter criteria, and does the following:
  * Fetches the function code from the cloud account
  * Verifies the signature of the function code image or zip file
  * Follows one of these actions, based on the verification results:
    * Detect - marks the function with the verification results
    * Block - tags the function as 'blocked', if the signature is not correctly verified, otherwise does nothing
    * Notify - sends a notification of the verification results to an SNS queue

If a function is tagged as blocked, it will be prevented from being run by AWS when it is invoked.

## Download FunctionClarity
- Download the latest `aws_function.tar.gz` and `functionclarity-vYYY<os_type>` files from: https://github.com/openclarity/functionclarity/releases

- Extract both files into the same directory:
  ```
  # tar -xzvf aws_function.tar.gz
  x aws_function

  # tar -xzvf functionclarity-v1.0.2-darwin-amd64.tar.gz
  x functionclarity unified
  x unified-template.template
  ```
  Other than the original gz files, there should be the following files in the same directory:
  ```
  aws_function
  functionclarity
  unified-template.template
  ```
**Note: Depending on the operating system that you are using to run the `functionclarity` binary, you may have to trust the binary. In MacOS, a warning will popup on first use of the functionclarity command. It will look similar to this:

![image](https://user-images.githubusercontent.com/3701244/207752284-f525db61-f1ff-46d5-9a40-d8a85982f0ef.png)

On a Mac, you can resolve this issue by going to Settings > Security & Privacy > Privacy > Developer Tools and checking the box next to "functionclarity" as shown here:

![image](https://user-images.githubusercontent.com/3701244/207755079-688c7a83-6e7b-4c5c-ba06-33c8fbe4aea8.png)

Go into Finder and locate the `functionclarity` binary and right-click on the file and click "open". Another popup will appear that looks like this:

![image](https://user-images.githubusercontent.com/3701244/207755405-9d784f33-f046-4955-bacc-fb4acc54f251.png)

A new terminal window will open and the command will run one time. You can close this terminal window if you use another terminal type like iTerm2 or you can leave it open for the additional FunctionClarity command-line steps below.

## AWS IAM Role / Policy Creation

If you do not already have an AWS Lambda role and policy defined, you will need to create one in order to deploy and interact with the AWS Lambda service.

Create a file and add the following to it:
```
# cat > trust-policy.json << EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "Service": "lambda.amazonaws.com"
            },
            "Action": "sts:AssumeRole"
        }
    ]
}
EOF
```
Create a new AWS IAM role for Lambda using the trust document you just created:
```
# aws iam create-role --role-name <my-lambda-role> \
    --assume-role-policy-document file://trust-policy.json > lambda-role.json
```

Attach the AWSLambdaBasicExecutionRole and the AWSLambda_ReadOnlyAccess policies to the role you just created:
```
# aws iam attach-role-policy --role-name <my-lambda-role> \
    --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole
# aws iam attach-role-policy --role-name <my-lambda-role> \
    --policy-arn arn:aws:iam::aws:policy/AWSLambda_ReadOnlyAccess
```
Look in the lambda-role.json file that was created during the IAM role creation step and copy the arn section (e.g., arn:aws:iam::<account_number>:role-<my-lambda-role>).

Export that ARN as a variable:
```
# export ROLE_ARN=arn:aws:iam::<account_number>:role-<my-lambda-role>
```

## Create a Sample Function

Create a directory called "src" and change to that directory
```
# cat > lambda_function.py  << EOF
import json

def lambda_handler(event, context):
    return {
        'statusCode': 200,
        'body': json.dumps('Hello from FunctionClarity!')
    }
EOF
```
Zip the code in the src/ directory and move the zip to base path:
```
# zip -r hello_world_function.zip lambda_function.py
# mv hello_world_function.zip ../
```
## Initialize FunctionClarity in the AWS Environment
Questions that needs answers:
- AWS Access Key (Required)
- AWS Secret key (Required)
- The AWS region you want FunctionClarity installed in (Required)
- Default AWS S3 Bucket for code signing storage (Optional if you have only one FunctionClarity instance across all regions). Note that the FunctionClarity S3 bucket name is global i.e if you have a FunctionClarity deployed per region, it is required to give each instance a unique name even if they are in deployed in different regions. Default sytem generated name is "FunctionClarity".
- Custom function tags you want to filter on (Optional. Blank scans for all functions. Tag example "sm-hello1" (This translates to key: sm-hello1, value:<blank-this-field-is-not-used>)
- Function regions (Optional. Blank scans all regions in this account. It is best to start off scanning one region and with specific function tags.) **Warning**: Using blank region filters and blank filter tags means FunctionClarity is scanning (and possibly blocking) ALL functions in ALL regions
- Post verification action (Required)
- SNS arn for notifications (Optional)
- Existing CloudTrail instance to use (Optional)
- Keyless mode (Optional. See documentation on this mode)
- Path for custom (existing) codesign key (Optional)
- Password to protect local private key that is created by FunctionClarity (Required)

```
# ./functionclarity init aws
```
Example output:
```
enter Access Key: <YOUR_ACCESS_KEY>
enter Secret Key: <YOUR_SECRET_KEY>
enter region: us-west-2
enter default bucket (you can leave empty and a bucket with name functionclarity will be created):
enter tag keys of functions to include in the verification (leave empty to include all): sm-hello1
enter the function regions to include in the verification, i.e: us-east-1,us-west-1 (leave empty to include all): us-west-2
select post verification action : (1) for detect; (2) for block; leave empty for no post verification action to perform: 2
enter SNS arn if you would like to be notified when signature verification fails, otherwise press enter:
is there existing trail in CloudTrail (in the region selected above) which you would like to use? (if no, please press enter):
do you want to work in keyless mode (y/n): n
enter path to custom public key for code signing? (if you want us to generate key pair, please press enter):
Enter password for private key:
Enter password for private key again:
File cosign.key already exists. Overwrite (y/n)? y
Private key written to cosign.key
Public key written to cosign.pub
Uploading function-clarity function code to s3 bucket, this may take a few minutes
function-clarity function code upload successfully
deployment request sent to provider
waiting for deployment to complete
deployment finished successfully
```

## Use FunctionClarity to Sign Your Code

```
./functionclarity sign aws code src/
```

Example output:
```
# ./functionclarity sign aws code src/
using config file: /Users/<ID>/.fc
Using payload from: /tmp/4f6957e8-6d94-4cf1-a5d0-6670889795ed
Enter password for private key:
Code uploaded successfully
```

## Create a Function in AWS Lambda

You can use whatever method you are familiar with to create a test function (Console, SAM, CLI). An example is provided below using the AWS CLI.

Make sure the previous steps for IAM role creation, policy attachment, exporting of the role ARN are completed.

Populate the various flags using the information from the previous steps:

```
# aws lambda create-function --function-name hello_world_function \
    --runtime python3.9 --timeout 10 --memory-size 128 \
    --architectures x86_64 --package-type=Zip \
    --handler lambda_function.lambda_handler \
    --zip-file fileb://hello_world_function.zip \
    --role ${ROLE_ARN} \
    --publish > lambda-function.json \
    --tags sm-hello1=
```

There is a new function in the AWS Lambda service console:

![image](https://user-images.githubusercontent.com/3701244/207760868-5bb1ceed-52c6-4f01-8d83-a5492f1176a2.png)

Setup a test event:

![image](https://user-images.githubusercontent.com/3701244/207761101-c0bcfd7e-c949-400f-8091-94c6d8d25dd4.png)

Run the test event:

![image](https://user-images.githubusercontent.com/3701244/207761232-7b4972e7-ece4-4c12-9e82-5edceee49655.png)

Edit the code, deploy the change and test the event. This will trigger FunctionClarity to compare the code with what it has previously signed.

![image](https://user-images.githubusercontent.com/3701244/207765219-0a81a2d5-ad59-4b85-ae6d-9385e5dc5d88.png)

FunctionClarity checks the new code against what was signed and blocks the function from running by dropping the function run concurrency to zero:

![image](https://user-images.githubusercontent.com/3701244/207765406-4c9f1fd0-af6f-4764-8b9d-8e3cb6266cd7.png)

In the FunctionClarity Verifier Function logs entries show the normal behavior at the bottom of the log window. This is what it looks like when a function runs the same code that was signed and verified.

The top part of the log is after the code was changed, but not signed and verified by FunctionClarity. The action we chose during the initization step was to 'block' functions that fail signing checks.

![image](https://user-images.githubusercontent.com/3701244/207761711-dd1f9d5a-6b53-4911-a108-e81a13805e77.png)


#### Verify manually
You can also use the CLI to manually verify a function. In this case, the function is downloaded from the cloud account, and then verified locally.

```shell
./functionclarity verify aws funcclarity-test-signed --function-region=us-east-2
using config file: /Users/john/.fc
Verified OK
```

## Advanced use
FunctionClarity includes several advanced commands and features, which are described below.

FunctionClarity leverages [cosign](https://github.com/sigstore/cosign) to sign and verify, code, for both  key-pair and keyless signing techniques.

### Init command detailed use
```shell
./functionclarity init aws
```
| Argument                       | Description                                                                                        |
|-----------------------------|----------------------------------------------------------------------------------------------------|
| access key                  | AWS access key                                                                                     |
| secret key                  | AWS secret key                                                                                     |
| region                      | AWS region in which to deploy FunctionClarity                                                                   |
| default bucket              | AWS bucket in which to deploy code signatures and FunctionClarity verifier lambda code for the deployment       |
| post verification action    | action to perform after verification (detect, block;  leave empty for no action to be performed)  |
| sns arn                     | an SNS queue for notifications if verification fails, leave empty to skip notifications                  |
| CloudTrail                  | AWS cloudtrail to use; if  empty a new trail will be created                                   |
| keyless mode (y/n)          | work in keyless mode                                              |
| public key for code signing | path to public key to use when verifying functions; if blank a new key-pair will be created |
| privte key for code signing | private key path; used only if a public key path is also supplied                   |
| function tag keys to include| tag keys of functions to include in the verification; if empty all functions will be included |
| function regions to include | function regions to include in the verification, i.e: us-east-1,us-west-1; if empty functions from all regions will be included |

| Flag               | Description                                                             |
|--------------------|-------------------------------------------------------------------------|
| only-create-config | determine whether to only create config file without actually deploying |

### Import your own signing key
The ```import-key-pair``` command provide the ability to import your existing PEM-encoded, RSA or EC private key, use this command:
```shell
./function-clarity import-key-pair --key key.pem
```

### Deploy command detailed use
The ```deploy``` command does the same as ```init```, but it uses the config file, so you don't
need to supply parameters  using the command line
```shell
./functionclarity deploy aws
```

### Sign command detailed use
FunctionClarity supports signing  code from local folders and images.
When signing images, you must be logged in to the docker repository where your images deployed.


---

**NOTE**:
If  a default config file exists (in  ```~/.fc```) it will be used. If a custom config file flag is included in the command line, it will be used instead of the default file. If flags are included in the command line, they will be used and take precedence.

---
### Examples
To sign code, use this command:
```shell
./functionclarity sign aws code <file/folder to sign> --flags (optional if you have configuration file)
```
To sign images, use this command:
```shell
./functionclarity sign aws image <image url> --flags (optional if you have configuration file)
```
These are optional flags for the ```sign```  command:

| flag       | Description                                                      |
|------------|------------------------------------------------------------------|
| access key | AWS access key                                                   |
| secret key | AWS secret key                                                   |
| region     | AWS region in which to deploy signature (relevant only for code signing)      |
| bucket     | AWS bucket in which to deploy code signature (relevant only for code signing) |
| privatekey | key to use to sign code                                            |


### Verify command detailed use

---

**NOTE**:
If  a default config file exists (in  ```~/.fc```) it will be used. If a custom config file flag is included in the command line, it will be used instead of the default file. If flags are included in the command line, they will be used and take precedence.

---

Command for verification
```shell
./functionclarity verify aws <function name to verify> --function-region=<function region location> --flags (optional if you have configuration file)
```

These are  optional flags for the ```verify``` command:

| flag       | Description                                                        |
|------------|--------------------------------------------------------------------|
| access key | AWS access key                                                     |
| secret key | AWS secret key                                                     |
| region     | AWS region from which  to load the signature from (relevant only for code signing) |
| bucket     | AWS bucket from which to load signatures from (relevant only for code signing)    |
| key        | public key for verification                                        |
