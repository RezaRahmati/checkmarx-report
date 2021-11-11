import * as fs from 'fs';
import * as path from 'path';
import dotenv from 'dotenv'
// import { default as fetch } from 'node-fetch';
import { globby } from 'globby';

dotenv.config();

(async () => {

    try {
        const xmlDir = process.env.XML_FOLDER;
        const templateFile = process.env.TEMPLATE_FILE;
        const outDir = process.env.OUTPUT_FOLDER;
        // Get the files as an array
        const xmlFiles = await globby([`${xmlDir}/**/*`]);

        const promises = [];

        for (const file of xmlFiles) {

            console.log("Processing '%s' started", file);

            promises.push(
                // fetch(process.env.API_URL, {
                //     method: 'POST',
                //     headers: {
                //         "api-key": process.env.API_KEY,
                //     },
                //     body: formData
                // }).then(res => res.json()).then((res) => {
                //     console.log("Processing '%s' done", res.fileName);
                //     return res;
                // })
            );

        }

        const responses = await Promise.allSettled(promises);
        const data = responses.map(r => {
            if (r.status === 'fulfilled') {
                const value = r.value;
            } else {
            }
        });

        const outputFile = path.join(outDir, `report-${getDate()}.docx`);
        console.log(`Report saved to ${outputFile}`);
        fs.writeFileSync(outputFile, "");
    }
    catch (e) {
        console.error("Whoops!", e);
    }

})();

const getDate = () => {
    return new Date().toLocaleString().replace(/[T,]/gi, '').replace(/[\/: ]/gi, '-');
}

