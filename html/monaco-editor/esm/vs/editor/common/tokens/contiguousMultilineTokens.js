export class ContiguousMultilineTokens{constructor(t,e){this._startLineNumber=t,this._tokens=e}get startLineNumber(){return this._startLineNumber}get endLineNumber(){return this._startLineNumber+this._tokens.length-1}getLineTokens(t){return this._tokens[t-this._startLineNumber]}appendLineTokens(t){this._tokens.push(t)}}