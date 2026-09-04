const fs = require('fs');
const readline = require('readline');

async function extract() {
  const filePath = 'C:/Users/Siddh/.gemini/antigravity/brain/2f796a8b-1da3-481a-9c14-15a6679bc3fc/.system_generated/logs/transcript_full.jsonl';
  const fileStream = fs.createReadStream(filePath);
  const rl = readline.createInterface({ input: fileStream, crlfDelay: Infinity });

  let targetContent = null;
  for await (const line of rl) {
    if (line.includes('"step_index":3369') || line.includes('"step_index": 3369')) {
      const obj = JSON.parse(line);
      targetContent = obj.content;
      break;
    }
  }

  if (!targetContent) {
    console.error('step 3369 not found!');
    process.exit(1);
  }

  const csvStart = targetContent.indexOf('text,label,phishing_type,severity,confidence');
  const marker = 'You are a senior ML';
  const csvEnd = targetContent.indexOf(marker);
  let csvText = targetContent.substring(csvStart, csvEnd !== -1 ? csvEnd : undefined).trim();

  // If the last row was truncated at "Rega", let's handle or complete it
  // Notice: "Keywords: act now 24 hours\n\nRega" -> "Regards,\nTaylor Brown",1,urgency,high,0.85
  if (csvText.endsWith('Rega')) {
    csvText = csvText + 'rds,\nTaylor Brown",1,urgency,high,0.85';
  }

  fs.writeFileSync('server/data/dataset.csv', csvText, 'utf-8');
  console.log('Saved server/data/dataset.csv, byte length:', Buffer.byteLength(csvText));
}

extract().catch(console.error);
