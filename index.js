import * as fs from 'fs';
import * as path from 'path';
import dotenv from 'dotenv'
// import { default as fetch } from 'node-fetch';
import { globby } from 'globby';
import * as convert from 'xml-js';
import _ from 'lodash';
import { createReport } from 'docx-templates';
import multisort from 'multisort';

dotenv.config();

(async () => {

    try {
        const xmlDir = process.env.XML_FOLDER;
        const templateFile = process.env.TEMPLATE_FILE;
        const outDir = process.env.OUTPUT_FOLDER;
        // Get the files as an array
        const xmlFiles = await globby([`${xmlDir}/**/*.xml`]);

        let fullJson = {};

        for (const file of xmlFiles) {

            console.log("Processing '%s' started", file);

            const xml = await fs.promises.readFile(file);

            const json = JSON.parse(convert.xml2json(xml, { compact: true, spaces: 4 }));

            fullJson = _.mergeWith({}, fullJson, json, (objValue, srcValue, key, object, source) => {
                if (_.isArray(objValue)) {
                    return objValue.concat(srcValue);
                }
            });

            console.log(fullJson.CxXMLResults.Query.length);
            console.log(Object.keys(fullJson.CxXMLResults.Query[0]));
            console.log(fullJson.CxXMLResults.Query.map(q => q._attributes.id).sort((a, b) => +a - +b));
        }

        const template = fs.readFileSync(templateFile);

        const buffer = await createReport({
            template,
            data: mapJsonToFlatData(fullJson),
            cmdDelimiter: ['{{', '}}'],
        });

        const outputFile = path.join(outDir, `report-${getDate()}.docx`);
        console.log(`Report saved to ${outputFile}`);

        fs.writeFileSync(outputFile, buffer)

    }
    catch (e) {
        console.error("Whoops!", e);
    }

})();

const getDate = () => {
    return new Date().toLocaleString().replace(/[T,]/gi, '').replace(/[\/: ]/gi, '-');
}

const mapJsonToFlatData = (data) => {
    const result = {
        name: 'Project X',
        summary: [],
        items: []
    };

    console.log(data.CxXMLResults.Query[0].Result[0].Path.PathNode[0].Snippet.Line.Code)

    result.summary = multisort(data.CxXMLResults.Query, ['~_attributes.SeverityIndex', '~Result.length'])
        .map(q => ({
            ...q,
            Result: _.isArray(q.Result) ? q.Result : [q.Result],
        }))
        .map(q => ({
            name: q._attributes.name,
            severity: q._attributes.Severity,
            language: q._attributes.Language,
            count: q.Result.length,
            items: q.Result.map(r => ({
                fileName: r._attributes.FileName,
                line: r._attributes.Line,
                snippet: r.Path && r.Path.PathNode && r.Path.PathNode.length && r.Path.PathNode[0].Snippet.Line.Code._text.trim()
            }))
        }));

    return result;
}

