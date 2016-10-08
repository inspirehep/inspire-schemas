#!/usr/bin/env node
//requires the json-schema-faker npm package installed
var fs = require('fs'),
    jsf = require('json-schema-faker'),
    path = require('path');

jsf.format('ISO 639-1', function(gen, schema){ return gen.randexp('^1.*$');});
jsf.format('date', function(gen, schema){ return gen.randexp('^1.*$');});
jsf.format('url', function(gen, schema){ return gen.randexp('^1.*$');});
jsf.format('isbn', function(gen, schema){ return gen.randexp('^1.*$');});
jsf.format('.+, .+', function(gen, schema){ return gen.randexp('^.+, .+$');});

function resolve_schema(unresolved_schema, base_path) {
    var keys = [];
    var resolved_schema = {};
    if (Array.isArray(unresolved_schema)) {
        new_array = []
            for (var value of unresolved_schema) {
                if (value !== null && typeof(value) === 'object') {
                    new_array = new_array.concat(resolve_schema(value, base_path))
                } else {
                    new_array = new_array.concat([value])
                }
            }
        return new_array
    }
    for (var key in unresolved_schema) {
        if (key === '$ref' && typeof(unresolved_schema[key]) === 'string') {
            var schema_path = base_path + "/" + unresolved_schema[key];
            var new_base_path = path.dirname(schema_path);
            var element_schema = JSON.parse(fs.readFileSync(schema_path));
            var resolved_element_schema = resolve_schema(element_schema, new_base_path);
            delete(resolved_element_schema['$schema'])
            return resolved_element_schema
        } else {
            if (resolved_schema['type'] === 'array' && !resolved_schema.hasOwnProperty('minItems')){
                resolved_schema['minItems'] = 1
            }
            if (resolved_schema.hasOwnProperty('properties') && !resolved_schema.hasOwnProperty('anyOf')) {
                resolved_schema['required'] = Object.keys(resolved_schema['properties'])
            }
            var value = unresolved_schema[key];
            if (value !== null && typeof(value) === 'object') {
                value = resolve_schema(unresolved_schema[key], base_path);
                delete(value['$schema'])
            }
            resolved_schema[key] = value
        }

    }
    return resolved_schema
}

var schemas = ['hep', 'authors', 'conferences', 'experiments', 'institutions', 'jobs', 'journals']
for (var schema_name of schemas) {
    console.log('Generating example for ' + schema_name)
    var data = fs.readFileSync('inspire_schemas/records/'+schema_name+'.json', 'utf8')
    var unresolved_schema = JSON.parse(data)
    var full_schema = resolve_schema(unresolved_schema, "inspire_schemas/records")
    var sample = jsf(full_schema)

    var outfile = schema_name + '_example.json'
    fs.writeFile(outfile, JSON.stringify(sample, null, 4))
    console.log('    Generated at ' + outfile)
}
