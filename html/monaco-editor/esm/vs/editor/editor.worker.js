import{SimpleWorkerServer}from"../base/common/worker/simpleWorker.js";import{EditorSimpleWorker}from"./common/services/editorSimpleWorker.js";let initialized=!1;export function initialize(e){if(initialized)return;initialized=!0;const i=new SimpleWorkerServer((e=>{self.postMessage(e)}),(i=>new EditorSimpleWorker(i,e)));self.onmessage=e=>{i.onmessage(e.data)}}self.onmessage=e=>{initialized||initialize(null)};