


///  N A T I V E

import { readFileSync } from "fs";

///  U T I L

import { args, run } from "./generate-hnssec.mjs";



///  P R O G R A M

parseJSONFile();

function parseJSONFile() {
  const data = JSON.parse(readFileSync("catalogue.json").toString()); /// replace with catalogue.sample.json to see what's generated
  const dataLength = data.length;
  const verbose = args["--verbose"];
  let count = 1;

  data.map(extension => {
    args["--name"] = extension.ascii;
    run(args);

    if (count < dataLength) {
      verbose && console.log(`\n[dolo] ${count}/${dataLength} processed`);
      count++;
    } else {
      verbose && console.log(`\n[dolo] ${count}/${dataLength} processed…complete`);
      !verbose && console.log("[dolo] Processing complete");
    }
  });
}
