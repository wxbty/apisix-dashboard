import{LcsDiff}from"../../../base/common/diff/diff.js";import*as strings from"../../../base/common/strings.js";const MINIMUM_MATCHING_CHARACTER_LENGTH=3;function computeDiff(e,i,t,n){const r=new LcsDiff(e,i,t);return r.ComputeDiff(n)}class LineSequence{constructor(e){const i=[],t=[];for(let n=0,r=e.length;n<r;n++)i[n]=getFirstNonBlankColumn(e[n],1),t[n]=getLastNonBlankColumn(e[n],1);this.lines=e,this._startColumns=i,this._endColumns=t}getElements(){const e=[];for(let i=0,t=this.lines.length;i<t;i++)e[i]=this.lines[i].substring(this._startColumns[i]-1,this._endColumns[i]-1);return e}getStrictElement(e){return this.lines[e]}getStartLineNumber(e){return e+1}getEndLineNumber(e){return e+1}createCharSequence(e,i,t){const n=[],r=[],o=[];let a=0;for(let s=i;s<=t;s++){const i=this.lines[s],t=e?this._startColumns[s]:1,h=e?this._endColumns[s]:i.length+1;for(let e=t;e<h;e++)n[a]=i.charCodeAt(e-1),r[a]=s+1,o[a]=e,a++}return new CharSequence(n,r,o)}}class CharSequence{constructor(e,i,t){this._charCodes=e,this._lineNumbers=i,this._columns=t}getElements(){return this._charCodes}getStartLineNumber(e){return this._lineNumbers[e]}getStartColumn(e){return this._columns[e]}getEndLineNumber(e){return this._lineNumbers[e]}getEndColumn(e){return this._columns[e]+1}}class CharChange{constructor(e,i,t,n,r,o,a,s){this.originalStartLineNumber=e,this.originalStartColumn=i,this.originalEndLineNumber=t,this.originalEndColumn=n,this.modifiedStartLineNumber=r,this.modifiedStartColumn=o,this.modifiedEndLineNumber=a,this.modifiedEndColumn=s}static createFromDiffChange(e,i,t){let n,r,o,a,s,h,l,m;return 0===e.originalLength?(n=0,r=0,o=0,a=0):(n=i.getStartLineNumber(e.originalStart),r=i.getStartColumn(e.originalStart),o=i.getEndLineNumber(e.originalStart+e.originalLength-1),a=i.getEndColumn(e.originalStart+e.originalLength-1)),0===e.modifiedLength?(s=0,h=0,l=0,m=0):(s=t.getStartLineNumber(e.modifiedStart),h=t.getStartColumn(e.modifiedStart),l=t.getEndLineNumber(e.modifiedStart+e.modifiedLength-1),m=t.getEndColumn(e.modifiedStart+e.modifiedLength-1)),new CharChange(n,r,o,a,s,h,l,m)}}function postProcessCharChanges(e){if(e.length<=1)return e;const i=[e[0]];let t=i[0];for(let n=1,r=e.length;n<r;n++){const r=e[n],o=r.originalStart-(t.originalStart+t.originalLength),a=r.modifiedStart-(t.modifiedStart+t.modifiedLength),s=Math.min(o,a);s<MINIMUM_MATCHING_CHARACTER_LENGTH?(t.originalLength=r.originalStart+r.originalLength-t.originalStart,t.modifiedLength=r.modifiedStart+r.modifiedLength-t.modifiedStart):(i.push(r),t=r)}return i}class LineChange{constructor(e,i,t,n,r){this.originalStartLineNumber=e,this.originalEndLineNumber=i,this.modifiedStartLineNumber=t,this.modifiedEndLineNumber=n,this.charChanges=r}static createFromDiffResult(e,i,t,n,r,o,a){let s,h,l,m,g;if(0===i.originalLength?(s=t.getStartLineNumber(i.originalStart)-1,h=0):(s=t.getStartLineNumber(i.originalStart),h=t.getEndLineNumber(i.originalStart+i.originalLength-1)),0===i.modifiedLength?(l=n.getStartLineNumber(i.modifiedStart)-1,m=0):(l=n.getStartLineNumber(i.modifiedStart),m=n.getEndLineNumber(i.modifiedStart+i.modifiedLength-1)),o&&i.originalLength>0&&i.originalLength<20&&i.modifiedLength>0&&i.modifiedLength<20&&r()){const o=t.createCharSequence(e,i.originalStart,i.originalStart+i.originalLength-1),s=n.createCharSequence(e,i.modifiedStart,i.modifiedStart+i.modifiedLength-1);let h=computeDiff(o,s,r,!0).changes;a&&(h=postProcessCharChanges(h)),g=[];for(let e=0,i=h.length;e<i;e++)g.push(CharChange.createFromDiffChange(h[e],o,s))}return new LineChange(s,h,l,m,g)}}export class DiffComputer{constructor(e,i,t){this.shouldComputeCharChanges=t.shouldComputeCharChanges,this.shouldPostProcessCharChanges=t.shouldPostProcessCharChanges,this.shouldIgnoreTrimWhitespace=t.shouldIgnoreTrimWhitespace,this.shouldMakePrettyDiff=t.shouldMakePrettyDiff,this.originalLines=e,this.modifiedLines=i,this.original=new LineSequence(e),this.modified=new LineSequence(i),this.continueLineDiff=createContinueProcessingPredicate(t.maxComputationTime),this.continueCharDiff=createContinueProcessingPredicate(0===t.maxComputationTime?0:Math.min(t.maxComputationTime,5e3))}computeDiff(){if(1===this.original.lines.length&&0===this.original.lines[0].length)return 1===this.modified.lines.length&&0===this.modified.lines[0].length?{quitEarly:!1,changes:[]}:{quitEarly:!1,changes:[{originalStartLineNumber:1,originalEndLineNumber:1,modifiedStartLineNumber:1,modifiedEndLineNumber:this.modified.lines.length,charChanges:[{modifiedEndColumn:0,modifiedEndLineNumber:0,modifiedStartColumn:0,modifiedStartLineNumber:0,originalEndColumn:0,originalEndLineNumber:0,originalStartColumn:0,originalStartLineNumber:0}]}]};if(1===this.modified.lines.length&&0===this.modified.lines[0].length)return{quitEarly:!1,changes:[{originalStartLineNumber:1,originalEndLineNumber:this.original.lines.length,modifiedStartLineNumber:1,modifiedEndLineNumber:1,charChanges:[{modifiedEndColumn:0,modifiedEndLineNumber:0,modifiedStartColumn:0,modifiedStartLineNumber:0,originalEndColumn:0,originalEndLineNumber:0,originalStartColumn:0,originalStartLineNumber:0}]}]};const e=computeDiff(this.original,this.modified,this.continueLineDiff,this.shouldMakePrettyDiff),i=e.changes,t=e.quitEarly;if(this.shouldIgnoreTrimWhitespace){const e=[];for(let t=0,n=i.length;t<n;t++)e.push(LineChange.createFromDiffResult(this.shouldIgnoreTrimWhitespace,i[t],this.original,this.modified,this.continueCharDiff,this.shouldComputeCharChanges,this.shouldPostProcessCharChanges));return{quitEarly:t,changes:e}}const n=[];let r=0,o=0;for(let a=-1,s=i.length;a<s;a++){const e=a+1<s?i[a+1]:null,t=e?e.originalStart:this.originalLines.length,h=e?e.modifiedStart:this.modifiedLines.length;while(r<t&&o<h){const e=this.originalLines[r],i=this.modifiedLines[o];if(e!==i){{let t=getFirstNonBlankColumn(e,1),a=getFirstNonBlankColumn(i,1);while(t>1&&a>1){const n=e.charCodeAt(t-2),r=i.charCodeAt(a-2);if(n!==r)break;t--,a--}(t>1||a>1)&&this._pushTrimWhitespaceCharChange(n,r+1,1,t,o+1,1,a)}{let t=getLastNonBlankColumn(e,1),a=getLastNonBlankColumn(i,1);const s=e.length+1,h=i.length+1;while(t<s&&a<h){const i=e.charCodeAt(t-1),n=e.charCodeAt(a-1);if(i!==n)break;t++,a++}(t<s||a<h)&&this._pushTrimWhitespaceCharChange(n,r+1,t,s,o+1,a,h)}}r++,o++}e&&(n.push(LineChange.createFromDiffResult(this.shouldIgnoreTrimWhitespace,e,this.original,this.modified,this.continueCharDiff,this.shouldComputeCharChanges,this.shouldPostProcessCharChanges)),r+=e.originalLength,o+=e.modifiedLength)}return{quitEarly:t,changes:n}}_pushTrimWhitespaceCharChange(e,i,t,n,r,o,a){if(this._mergeTrimWhitespaceCharChange(e,i,t,n,r,o,a))return;let s;this.shouldComputeCharChanges&&(s=[new CharChange(i,t,i,n,r,o,r,a)]),e.push(new LineChange(i,i,r,r,s))}_mergeTrimWhitespaceCharChange(e,i,t,n,r,o,a){const s=e.length;if(0===s)return!1;const h=e[s-1];return 0!==h.originalEndLineNumber&&0!==h.modifiedEndLineNumber&&(h.originalEndLineNumber+1===i&&h.modifiedEndLineNumber+1===r&&(h.originalEndLineNumber=i,h.modifiedEndLineNumber=r,this.shouldComputeCharChanges&&h.charChanges&&h.charChanges.push(new CharChange(i,t,i,n,r,o,r,a)),!0))}}function getFirstNonBlankColumn(e,i){const t=strings.firstNonWhitespaceIndex(e);return-1===t?i:t+1}function getLastNonBlankColumn(e,i){const t=strings.lastNonWhitespaceIndex(e);return-1===t?i:t+2}function createContinueProcessingPredicate(e){if(0===e)return()=>!0;const i=Date.now();return()=>Date.now()-i<e}