const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');

// Exercise the actual dashboard script with DOM elements that reject HTML sinks.
class Element {
    constructor(tag) {
        this.tagName = tag;
        this.childNodes = [];
        this.style = {};
        this.textContent = '';
        this.className = '';
    }
    set innerHTML(value) { throw new Error('Untrusted HTML sink used'); }
    appendChild(child) { this.childNodes.push(child); }
    append(...children) { this.childNodes.push(...children); }
    replaceChildren(...children) { this.childNodes = children; }
    get firstChild() { return this.childNodes[0]; }
}

test('manifest fields render as text and repeated scans replace rows', () => {
    const source = fs.readFileSync(path.join(__dirname, '../agentwall_supply/server.py'), 'utf8');
    const script = source.match(/<script>([\s\S]*?)<\/script>/)[1];
    const elements = new Map();
    const context = vm.createContext({ document: {
        getElementById(id) {
            if (!elements.has(id)) elements.set(id, new Element('div'));
            return elements.get(id);
        },
        createElement: tag => new Element(tag),
        querySelectorAll: () => [],
        querySelector: () => null,
    }});
    vm.runInContext(script, context);
    const attack = '<img src=x onerror="globalThis.compromised=true">';
    context.report = { score: 80, tier: 'HIGH', tools: [{
        name: attack, score: 80, tier: 'HIGH',
        injection_findings: [{ label: attack }], permission_categories: [attack],
    }] };
    vm.runInContext('renderReport(report)', context);
    const body = elements.get('toolsBody');
    const cells = body.childNodes[0].childNodes;
    assert.equal(cells[0].textContent, attack);
    assert.equal(cells[1].textContent, '80/100');
    assert.equal(cells[2].firstChild.textContent, 'HIGH');
    assert.equal(cells[3].childNodes[0].textContent, attack);
    assert.equal(cells[3].childNodes[1].textContent, `scope:${attack}`);
    assert.equal(context.compromised, undefined);
    context.report.tools[0].injection_findings = [];
    context.report.tools[0].permission_categories = [];
    vm.runInContext('renderReport(report)', context);
    assert.equal(body.childNodes.length, 1);
    assert.equal(body.childNodes[0].childNodes[3].firstChild.textContent, 'Clean');
});
