import{distinct}from"../../../../base/common/arrays.js";import{ignoreBracketsInToken}from"../supports.js";import{BracketsUtils}from"./richEditBrackets.js";export class BracketElectricCharacterSupport{constructor(t){this._richEditBrackets=t}getElectricCharacters(){const t=[];if(this._richEditBrackets)for(const r of this._richEditBrackets.brackets)for(const e of r.close){const r=e.charAt(e.length-1);t.push(r)}return distinct(t)}onElectricCharacter(t,r,e){if(!this._richEditBrackets||0===this._richEditBrackets.brackets.length)return null;const s=r.findTokenIndexAtOffset(e-1);if(ignoreBracketsInToken(r.getStandardTokenType(s)))return null;const n=this._richEditBrackets.reversedRegex,c=r.getLineContent().substring(0,e-1)+t,i=BracketsUtils.findPrevBracketInRange(n,1,c,0,c.length);if(!i)return null;const o=c.substring(i.startColumn-1,i.endColumn-1).toLowerCase(),a=this._richEditBrackets.textIsOpenBracket[o];if(a)return null;const h=r.getActualLineContentBefore(i.startColumn-1);return/^\s*$/.test(h)?{matchOpenBracket:o}:null}}