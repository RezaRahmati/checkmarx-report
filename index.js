import * as fs from 'fs';
import * as path from 'path';
import dotenv from 'dotenv'
import { globby } from 'globby';
import * as convert from 'xml-js';
import { createReport } from 'docx-templates';
import multisort from 'multisort';
import moment from 'moment';
import { CategoryInfo } from './category-info.js';

dotenv.config();

(async () => {

    try {
        console.time('Done');

        const xmlDir = process.env.XML_FOLDER;
        const templateFile = process.env.TEMPLATE_FILE;
        const outDir = process.env.OUTPUT_FOLDER;

        // Get the files as an array
        const xmlFiles = await globby([`${xmlDir}/**/*.xml`]);

        let fullJson = {};

        for (const file of xmlFiles) {

            console.log("Reading '%s' ", file);

            const xml = await fs.promises.readFile(file);

            const json = JSON.parse(convert.xml2json(xml, { compact: true, spaces: 4 }));

            json.CxXMLResults.Query = json.CxXMLResults.Query.map(q => ({
                ...q,
                Result: Array.isArray(q.Result) ? q.Result : [q.Result],
            }));

            fullJson = json.CxXMLResults.Query.reduce((acc, q) => {
                const id = q._attributes.id;
                q._attributes.name = q._attributes.name.replace(/_/g, ' ');

                if (!acc[id]) {
                    acc[id] = q;
                } else {
                    acc[id].Result = [...acc[id].Result, ...q.Result];
                }

                return acc;
            }, fullJson)
        }

        const data = mapJsonToFlatData(fullJson);

        console.log("Reading template '%s' ", templateFile);
        const template = fs.readFileSync(templateFile);

        console.log("Generating output");
        console.time('Generating output');
        const buffer = await createReport({
            template,
            data: data,
            cmdDelimiter: ['{{', '}}'],
        });
        console.timeEnd('Generating output');

        const outputFile = path.join(outDir, `report-${getDate()}.docx`);
        console.log("Saving output '%s'", outputFile);

        fs.writeFileSync(outputFile, buffer)

        console.timeEnd('Done')

    }
    catch (e) {
        console.error("Whoops!", e);
    }

})();

const getDate = () => {
    return moment().format('YYYY-MM-DD-HH-mm');
}

const mapJsonToFlatData = (data) => {
    const result = {
        name: process.env.PROJECT || 'Project Name',
        summary: [],
        severity: {
            high: null,
            medium: null,
            low: null,
            info: null,
            sum: null
        }
    };

    const values = Object.values(data);

    console.log('Categories', values.length);
    values.map(v => `\t[${v._attributes.id}] ${v._attributes.name} (${v.Result.length})`).forEach(i => console.log(i));

    values.forEach(v => {
        if (!CategoryInfo[v._attributes.id]) {
            console.warn(`Category info for [${v._attributes.id}] ${v._attributes.name} not found. https://crttti.checkmarx.net/cxwebclient/ScanQueryDescription.aspx?queryID=${v._attributes.id}`)
        }
    })

    Object.keys(CategoryInfo).forEach(k => {
        CategoryInfo[k].risk = (CategoryInfo[k].risk || '').trim();
        CategoryInfo[k].cause = (CategoryInfo[k].cause || '').trim();
        CategoryInfo[k].recommendation = (CategoryInfo[k].recommendation || '').trim();
    })


    result.summary = multisort(values, ['~_attributes.SeverityIndex', '~Result.length'])
        .map(q => ({
            name: q._attributes.name,
            severity: q._attributes.Severity,
            SeverityIndex: q._attributes.SeverityIndex,
            language: q._attributes.Language,
            count: q.Result.length,
            info: CategoryInfo[q._attributes.id] ? { ...CategoryInfo[q._attributes.id] } : {
                risk: '',
                cause: '',
                recommendation: '',
            },
            items: q.Result.map(r => {
                let pathNodes = [];
                if (r.Path && r.Path.PathNode) {
                    if (!Array.isArray(r.Path.PathNode)) {
                        pathNodes = [r.Path.PathNode];
                    } else {
                        pathNodes = r.Path.PathNode;
                    }
                }
                const result = {
                    fileName: r._attributes.FileName,
                    line: r._attributes.Line,
                    column: r._attributes.Column,
                    severity: r._attributes.Severity,
                    SeverityIndex: r._attributes.SeverityIndex,
                    snippet: pathNodes && pathNodes.length && pathNodes[0].Snippet.Line.Code._text.trim(),
                    callStack: pathNodes.map(p => ({
                        fileName: p.FileName && p.FileName._text,
                        line: p.Line && p.Line._text,
                        column: p.Line && p.Column._text,
                        name: p.Name && p.Name._text,
                        snippet: p.Snippet.Line.Code._text.trim()
                    }))
                };
                return result;
            })
        }));

    const flatResults = values.map(q => q.Result).flat() || [];

    result.severity = {
        high: flatResults.filter(q => q._attributes.SeverityIndex == 3).length,
        medium: flatResults.filter(q => q._attributes.SeverityIndex == 2).length,
        low: flatResults.filter(q => q._attributes.SeverityIndex == 1).length,
        info: flatResults.filter(q => q._attributes.SeverityIndex == 0).length,
        sum: null
    }

    result.severity.sum = result.severity.high + result.severity.medium + result.severity.low + result.severity.info;

    console.log('Severity Summary', result.severity);

    return result;
}

