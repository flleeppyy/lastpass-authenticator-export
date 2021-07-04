import axios from "axios";
import cryptojs from "crypto-js";
import crypto, { pbkdf2Sync } from "crypto";
import read from "read";
import PBKDF2 from "pbkdf2";
import base64 from "js-base64";
import yargs from "yargs";
import { hideBin } from "yargs/helpers";
import { encrypt } from "./lastpass-src/encryption/aes/ebc";

interface loginData {
  method: string;
  web: number;
  xml: number;
  username: string;
  encrypted_username: string;
  hash: string | Buffer;
  iterations: number;
  otp?: number;
}

const base_url = "https://lastpass.com";
const axiosInstance = axios.create({ baseURL: base_url });

async function iterations(username: string) {
  const url = "https://lastpass.com/iterations.php";

  const result = axios.get(url, {
    params: {
      email: username,
    },
  });
  const res = await result;
  return Number(res.data);
}

function crtHash(username: string, password: string, iteration_count: number) {
  const key = PBKDF2.pbkdf2Sync(password, username, iteration_count, 32);
  
}
async function login(
  username: string,
  password: string,
  otp: number = undefined,
) {
  username = username.toLowerCase().trim();
  const iteration_count = await iterations(username);
  const key = crtHash.key;
  const hash = encrypt()
  // console.log(login_hash);
  const data: loginData = {
    method: "mobile",
    web: 1,
    xml: 1,
    username: username,
    encrypted_username: (await encrypt(username, key)).toString("base64"),
    hash: hash,
    iterations: iteration_count,
  };

  console.log(data);

  if (otp) {
    data.otp = otp;
  }

  const response = await axiosInstance.post(base_url + "/login.php", data);
  if (!response.data.startsWith("<ok")) {
    console.error("Login failed!");
    console.log(response.data);
    process.exit(1);
  } else {
    const phpsessid: string = response.headers["set-cookie"][0]; //.split("; ")[0].split("=")[1];
    axiosInstance.defaults.headers.Cookie = phpsessid;
    const csrf: string = (await axiosInstance.post("/getCSRFTOken.php")).data;
    const returnData = {phpsessid, csrf, key};
    return returnData;
  }
}

async function getMfaBackup(session: string, csrf: string) {
  const url = "https://lastpass.com/lmiapi/authenticator/backup";
  const headers = {
    "X-CSRF-TOKEN": csrf,
    "X-SESSION-ID": session,
  };

  const r = await axios.get(url, {
    headers: headers,
  });

  const parsed = JSON.parse(r.data);
  return parsed["userData"];
}

function decryptUserData(user_data: string, key: Buffer) {
  const data_parts = user_data.split("|");
  const iv = base64.decode(data_parts[0].split("!")[1]);
  const ciphertext = base64.decode(data_parts[1]);

  // const cipher = cryptojs.AES.encrypt(key, AES,{
  //   "iv": iv
  // });
}


function getpass() {
  return new Promise<string>((resolve, reject) => {
    read({silent: true, prompt: "Password: "}, (error, result: string, isDefault) => {
      if (error) {
        reject(error);
      } else {
        resolve(result);
      }


    });
  });
}

function getArgs() {
  const usage =
    "Usage: index.ts [--username: LastPass Username/Email] {--otp: LastPass OTP}";
  const args = yargs(hideBin(process.argv)).argv;

  if (!args["username"]) {
    console.error(usage);
    process.exit(0);
  }

  if (args["otp"] && isNaN(args["otp"]) === true) {
    console.error("OTP is not a number.");
    process.exit(1);
  } else if (args["otp"] > 6) {
    console.error("OTP is longer than 6 digits");
    process.exit(1);
  }

  return args;
}

async function main() {
  const args = getArgs();
  const username = args["username"];
  const otp = args["otp"] ? args["otp"] : undefined;
  const password = (await getpass());

  login(username, password, otp, (phpsessid, csrf, key) => {
    console.log(
      `PHPSESSID: ${phpsessid}\n` +
      `CSRF: ${csrf}\n` +
      `KEY: ${key.toString()}\n`
    );
  });


}

main();
