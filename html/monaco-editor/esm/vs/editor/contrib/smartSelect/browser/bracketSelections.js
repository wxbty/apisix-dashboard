var __awaiter=this&&this.__awaiter||function(e,t,n,i){function o(e){return e instanceof n?e:new n((function(t){t(e)}))}return new(n||(n=Promise))((function(n,a){function r(e){try{c(i.next(e))}catch(t){a(t)}}function s(e){try{c(i["throw"](e))}catch(t){a(t)}}function c(e){e.done?n(e.value):o(e.value).then(r,s)}c((i=i.apply(e,t||[])).next())}))};import{LinkedList}from"../../../../base/common/linkedList.js";import{Position}from"../../../common/core/position.js";import{Range}from"../../../common/core/range.js";export class BracketSelectionRangeProvider{provideSelectionRanges(e,t){return __awaiter(this,void 0,void 0,(function*(){const n=[];for(const i of t){const t=[];n.push(t);const o=new Map;yield new Promise((t=>BracketSelectionRangeProvider._bracketsRightYield(t,0,e,i,o))),yield new Promise((n=>BracketSelectionRangeProvider._bracketsLeftYield(n,0,e,i,o,t)))}return n}))}static _bracketsRightYield(e,t,n,i,o){const a=new Map,r=Date.now();while(1){if(t>=BracketSelectionRangeProvider._maxRounds){e();break}if(!i){e();break}let s=n.bracketPairs.findNextBracket(i);if(!s){e();break}let c=Date.now()-r;if(c>BracketSelectionRangeProvider._maxDuration){setTimeout((()=>BracketSelectionRangeProvider._bracketsRightYield(e,t+1,n,i,o)));break}const g=s.close[0];if(s.isOpen){let e=a.has(g)?a.get(g):0;a.set(g,e+1)}else{let e=a.has(g)?a.get(g):0;if(e-=1,a.set(g,Math.max(0,e)),e<0){let e=o.get(g);e||(e=new LinkedList,o.set(g,e)),e.push(s.range)}}i=s.range.getEndPosition()}}static _bracketsLeftYield(e,t,n,i,o,a){const r=new Map,s=Date.now();while(1){if(t>=BracketSelectionRangeProvider._maxRounds&&0===o.size){e();break}if(!i){e();break}let c=n.bracketPairs.findPrevBracket(i);if(!c){e();break}let g=Date.now()-s;if(g>BracketSelectionRangeProvider._maxDuration){setTimeout((()=>BracketSelectionRangeProvider._bracketsLeftYield(e,t+1,n,i,o,a)));break}const l=c.close[0];if(c.isOpen){let e=r.has(l)?r.get(l):0;if(e-=1,r.set(l,Math.max(0,e)),e<0){let e=o.get(l);if(e){let t=e.shift();0===e.size&&o.delete(l);const i=Range.fromPositions(c.range.getEndPosition(),t.getStartPosition()),r=Range.fromPositions(c.range.getStartPosition(),t.getEndPosition());a.push({range:i}),a.push({range:r}),BracketSelectionRangeProvider._addBracketLeading(n,r,a)}}}else{let e=r.has(l)?r.get(l):0;r.set(l,e+1)}i=c.range.getStartPosition()}}static _addBracketLeading(e,t,n){if(t.startLineNumber===t.endLineNumber)return;const i=t.startLineNumber,o=e.getLineFirstNonWhitespaceColumn(i);0!==o&&o!==t.startColumn&&(n.push({range:Range.fromPositions(new Position(i,o),t.getEndPosition())}),n.push({range:Range.fromPositions(new Position(i,1),t.getEndPosition())}));const a=i-1;if(a>0){const i=e.getLineFirstNonWhitespaceColumn(a);i===t.startColumn&&i!==e.getLineLastNonWhitespaceColumn(a)&&(n.push({range:Range.fromPositions(new Position(a,i),t.getEndPosition())}),n.push({range:Range.fromPositions(new Position(a,1),t.getEndPosition())}))}}}BracketSelectionRangeProvider._maxDuration=30,BracketSelectionRangeProvider._maxRounds=2;