import{isChrome,isEdge,isFirefox,isLinux,isMacintosh,isSafari,isWeb,isWindows}from"../../../base/common/platform.js";import{isFalsyOrWhitespace}from"../../../base/common/strings.js";import{createDecorator}from"../../instantiation/common/instantiation.js";const CONSTANT_VALUES=new Map;CONSTANT_VALUES.set("false",!1),CONSTANT_VALUES.set("true",!0),CONSTANT_VALUES.set("isMac",isMacintosh),CONSTANT_VALUES.set("isLinux",isLinux),CONSTANT_VALUES.set("isWindows",isWindows),CONSTANT_VALUES.set("isWeb",isWeb),CONSTANT_VALUES.set("isMacNative",isMacintosh&&!isWeb),CONSTANT_VALUES.set("isEdge",isEdge),CONSTANT_VALUES.set("isFirefox",isFirefox),CONSTANT_VALUES.set("isChrome",isChrome),CONSTANT_VALUES.set("isSafari",isSafari);const hasOwnProperty=Object.prototype.hasOwnProperty;export class ContextKeyExpr{static has(e){return ContextKeyDefinedExpr.create(e)}static equals(e,t){return ContextKeyEqualsExpr.create(e,t)}static regex(e,t){return ContextKeyRegexExpr.create(e,t)}static not(e){return ContextKeyNotExpr.create(e)}static and(...e){return ContextKeyAndExpr.create(e,null)}static or(...e){return ContextKeyOrExpr.create(e,null,!0)}static deserialize(e,t=!1){if(e)return this._deserializeOrExpression(e,t)}static _deserializeOrExpression(e,t){let r=e.split("||");return ContextKeyOrExpr.create(r.map((e=>this._deserializeAndExpression(e,t))),null,!0)}static _deserializeAndExpression(e,t){let r=e.split("&&");return ContextKeyAndExpr.create(r.map((e=>this._deserializeOne(e,t))),null)}static _deserializeOne(e,t){if(e=e.trim(),e.indexOf("!=")>=0){let r=e.split("!=");return ContextKeyNotEqualsExpr.create(r[0].trim(),this._deserializeValue(r[1],t))}if(e.indexOf("==")>=0){let r=e.split("==");return ContextKeyEqualsExpr.create(r[0].trim(),this._deserializeValue(r[1],t))}if(e.indexOf("=~")>=0){let r=e.split("=~");return ContextKeyRegexExpr.create(r[0].trim(),this._deserializeRegexValue(r[1],t))}if(e.indexOf(" in ")>=0){let t=e.split(" in ");return ContextKeyInExpr.create(t[0].trim(),t[1].trim())}if(/^[^<=>]+>=[^<=>]+$/.test(e)){const t=e.split(">=");return ContextKeyGreaterEqualsExpr.create(t[0].trim(),t[1].trim())}if(/^[^<=>]+>[^<=>]+$/.test(e)){const t=e.split(">");return ContextKeyGreaterExpr.create(t[0].trim(),t[1].trim())}if(/^[^<=>]+<=[^<=>]+$/.test(e)){const t=e.split("<=");return ContextKeySmallerEqualsExpr.create(t[0].trim(),t[1].trim())}if(/^[^<=>]+<[^<=>]+$/.test(e)){const t=e.split("<");return ContextKeySmallerExpr.create(t[0].trim(),t[1].trim())}return/^\!\s*/.test(e)?ContextKeyNotExpr.create(e.substr(1).trim()):ContextKeyDefinedExpr.create(e)}static _deserializeValue(e,t){if(e=e.trim(),"true"===e)return!0;if("false"===e)return!1;let r=/^'([^']*)'$/.exec(e);return r?r[1].trim():e}static _deserializeRegexValue(e,t){if(isFalsyOrWhitespace(e)){if(t)throw new Error("missing regexp-value for =~-expression");return console.warn("missing regexp-value for =~-expression"),null}let r=e.indexOf("/"),s=e.lastIndexOf("/");if(r===s||r<0){if(t)throw new Error(`bad regexp-value '${e}', missing /-enclosure`);return console.warn(`bad regexp-value '${e}', missing /-enclosure`),null}let n=e.slice(r+1,s),i="i"===e[s+1]?"i":"";try{return new RegExp(n,i)}catch(a){if(t)throw new Error(`bad regexp-value '${e}', parse error: ${a}`);return console.warn(`bad regexp-value '${e}', parse error: ${a}`),null}}}export function expressionsAreEqualWithConstantSubstitution(e,t){const r=e?e.substituteConstants():void 0,s=t?t.substituteConstants():void 0;return!r&&!s||!(!r||!s)&&r.equals(s)}function cmp(e,t){return e.cmp(t)}export class ContextKeyFalseExpr{constructor(){this.type=0}cmp(e){return this.type-e.type}equals(e){return e.type===this.type}substituteConstants(){return this}evaluate(e){return!1}serialize(){return"false"}keys(){return[]}negate(){return ContextKeyTrueExpr.INSTANCE}}ContextKeyFalseExpr.INSTANCE=new ContextKeyFalseExpr;export class ContextKeyTrueExpr{constructor(){this.type=1}cmp(e){return this.type-e.type}equals(e){return e.type===this.type}substituteConstants(){return this}evaluate(e){return!0}serialize(){return"true"}keys(){return[]}negate(){return ContextKeyFalseExpr.INSTANCE}}ContextKeyTrueExpr.INSTANCE=new ContextKeyTrueExpr;export class ContextKeyDefinedExpr{constructor(e,t){this.key=e,this.negated=t,this.type=2}static create(e,t=null){const r=CONSTANT_VALUES.get(e);return"boolean"===typeof r?r?ContextKeyTrueExpr.INSTANCE:ContextKeyFalseExpr.INSTANCE:new ContextKeyDefinedExpr(e,t)}cmp(e){return e.type!==this.type?this.type-e.type:cmp1(this.key,e.key)}equals(e){return e.type===this.type&&this.key===e.key}substituteConstants(){const e=CONSTANT_VALUES.get(this.key);return"boolean"===typeof e?e?ContextKeyTrueExpr.INSTANCE:ContextKeyFalseExpr.INSTANCE:this}evaluate(e){return!!e.getValue(this.key)}serialize(){return this.key}keys(){return[this.key]}negate(){return this.negated||(this.negated=ContextKeyNotExpr.create(this.key,this)),this.negated}}export class ContextKeyEqualsExpr{constructor(e,t,r){this.key=e,this.value=t,this.negated=r,this.type=4}static create(e,t,r=null){if("boolean"===typeof t)return t?ContextKeyDefinedExpr.create(e,r):ContextKeyNotExpr.create(e,r);const s=CONSTANT_VALUES.get(e);if("boolean"===typeof s){const e=s?"true":"false";return t===e?ContextKeyTrueExpr.INSTANCE:ContextKeyFalseExpr.INSTANCE}return new ContextKeyEqualsExpr(e,t,r)}cmp(e){return e.type!==this.type?this.type-e.type:cmp2(this.key,this.value,e.key,e.value)}equals(e){return e.type===this.type&&(this.key===e.key&&this.value===e.value)}substituteConstants(){const e=CONSTANT_VALUES.get(this.key);if("boolean"===typeof e){const t=e?"true":"false";return this.value===t?ContextKeyTrueExpr.INSTANCE:ContextKeyFalseExpr.INSTANCE}return this}evaluate(e){return e.getValue(this.key)==this.value}serialize(){return`${this.key} == '${this.value}'`}keys(){return[this.key]}negate(){return this.negated||(this.negated=ContextKeyNotEqualsExpr.create(this.key,this.value,this)),this.negated}}export class ContextKeyInExpr{constructor(e,t){this.key=e,this.valueKey=t,this.type=10,this.negated=null}static create(e,t){return new ContextKeyInExpr(e,t)}cmp(e){return e.type!==this.type?this.type-e.type:cmp2(this.key,this.valueKey,e.key,e.valueKey)}equals(e){return e.type===this.type&&(this.key===e.key&&this.valueKey===e.valueKey)}substituteConstants(){return this}evaluate(e){const t=e.getValue(this.valueKey),r=e.getValue(this.key);return Array.isArray(t)?t.indexOf(r)>=0:"string"===typeof r&&"object"===typeof t&&null!==t&&hasOwnProperty.call(t,r)}serialize(){return`${this.key} in '${this.valueKey}'`}keys(){return[this.key,this.valueKey]}negate(){return this.negated||(this.negated=ContextKeyNotInExpr.create(this)),this.negated}}export class ContextKeyNotInExpr{constructor(e){this._actual=e,this.type=11}static create(e){return new ContextKeyNotInExpr(e)}cmp(e){return e.type!==this.type?this.type-e.type:this._actual.cmp(e._actual)}equals(e){return e.type===this.type&&this._actual.equals(e._actual)}substituteConstants(){return this}evaluate(e){return!this._actual.evaluate(e)}serialize(){throw new Error("Method not implemented.")}keys(){return this._actual.keys()}negate(){return this._actual}}export class ContextKeyNotEqualsExpr{constructor(e,t,r){this.key=e,this.value=t,this.negated=r,this.type=5}static create(e,t,r=null){if("boolean"===typeof t)return t?ContextKeyNotExpr.create(e,r):ContextKeyDefinedExpr.create(e,r);const s=CONSTANT_VALUES.get(e);if("boolean"===typeof s){const e=s?"true":"false";return t===e?ContextKeyFalseExpr.INSTANCE:ContextKeyTrueExpr.INSTANCE}return new ContextKeyNotEqualsExpr(e,t,r)}cmp(e){return e.type!==this.type?this.type-e.type:cmp2(this.key,this.value,e.key,e.value)}equals(e){return e.type===this.type&&(this.key===e.key&&this.value===e.value)}substituteConstants(){const e=CONSTANT_VALUES.get(this.key);if("boolean"===typeof e){const t=e?"true":"false";return this.value===t?ContextKeyFalseExpr.INSTANCE:ContextKeyTrueExpr.INSTANCE}return this}evaluate(e){return e.getValue(this.key)!=this.value}serialize(){return`${this.key} != '${this.value}'`}keys(){return[this.key]}negate(){return this.negated||(this.negated=ContextKeyEqualsExpr.create(this.key,this.value,this)),this.negated}}export class ContextKeyNotExpr{constructor(e,t){this.key=e,this.negated=t,this.type=3}static create(e,t=null){const r=CONSTANT_VALUES.get(e);return"boolean"===typeof r?r?ContextKeyFalseExpr.INSTANCE:ContextKeyTrueExpr.INSTANCE:new ContextKeyNotExpr(e,t)}cmp(e){return e.type!==this.type?this.type-e.type:cmp1(this.key,e.key)}equals(e){return e.type===this.type&&this.key===e.key}substituteConstants(){const e=CONSTANT_VALUES.get(this.key);return"boolean"===typeof e?e?ContextKeyFalseExpr.INSTANCE:ContextKeyTrueExpr.INSTANCE:this}evaluate(e){return!e.getValue(this.key)}serialize(){return`!${this.key}`}keys(){return[this.key]}negate(){return this.negated||(this.negated=ContextKeyDefinedExpr.create(this.key,this)),this.negated}}function withFloatOrStr(e,t){if("string"===typeof e){const t=parseFloat(e);isNaN(t)||(e=t)}return"string"===typeof e||"number"===typeof e?t(e):ContextKeyFalseExpr.INSTANCE}export class ContextKeyGreaterExpr{constructor(e,t,r){this.key=e,this.value=t,this.negated=r,this.type=12}static create(e,t,r=null){return withFloatOrStr(t,(t=>new ContextKeyGreaterExpr(e,t,r)))}cmp(e){return e.type!==this.type?this.type-e.type:cmp2(this.key,this.value,e.key,e.value)}equals(e){return e.type===this.type&&(this.key===e.key&&this.value===e.value)}substituteConstants(){return this}evaluate(e){return"string"!==typeof this.value&&parseFloat(e.getValue(this.key))>this.value}serialize(){return`${this.key} > ${this.value}`}keys(){return[this.key]}negate(){return this.negated||(this.negated=ContextKeySmallerEqualsExpr.create(this.key,this.value,this)),this.negated}}export class ContextKeyGreaterEqualsExpr{constructor(e,t,r){this.key=e,this.value=t,this.negated=r,this.type=13}static create(e,t,r=null){return withFloatOrStr(t,(t=>new ContextKeyGreaterEqualsExpr(e,t,r)))}cmp(e){return e.type!==this.type?this.type-e.type:cmp2(this.key,this.value,e.key,e.value)}equals(e){return e.type===this.type&&(this.key===e.key&&this.value===e.value)}substituteConstants(){return this}evaluate(e){return"string"!==typeof this.value&&parseFloat(e.getValue(this.key))>=this.value}serialize(){return`${this.key} >= ${this.value}`}keys(){return[this.key]}negate(){return this.negated||(this.negated=ContextKeySmallerExpr.create(this.key,this.value,this)),this.negated}}export class ContextKeySmallerExpr{constructor(e,t,r){this.key=e,this.value=t,this.negated=r,this.type=14}static create(e,t,r=null){return withFloatOrStr(t,(t=>new ContextKeySmallerExpr(e,t,r)))}cmp(e){return e.type!==this.type?this.type-e.type:cmp2(this.key,this.value,e.key,e.value)}equals(e){return e.type===this.type&&(this.key===e.key&&this.value===e.value)}substituteConstants(){return this}evaluate(e){return"string"!==typeof this.value&&parseFloat(e.getValue(this.key))<this.value}serialize(){return`${this.key} < ${this.value}`}keys(){return[this.key]}negate(){return this.negated||(this.negated=ContextKeyGreaterEqualsExpr.create(this.key,this.value,this)),this.negated}}export class ContextKeySmallerEqualsExpr{constructor(e,t,r){this.key=e,this.value=t,this.negated=r,this.type=15}static create(e,t,r=null){return withFloatOrStr(t,(t=>new ContextKeySmallerEqualsExpr(e,t,r)))}cmp(e){return e.type!==this.type?this.type-e.type:cmp2(this.key,this.value,e.key,e.value)}equals(e){return e.type===this.type&&(this.key===e.key&&this.value===e.value)}substituteConstants(){return this}evaluate(e){return"string"!==typeof this.value&&parseFloat(e.getValue(this.key))<=this.value}serialize(){return`${this.key} <= ${this.value}`}keys(){return[this.key]}negate(){return this.negated||(this.negated=ContextKeyGreaterExpr.create(this.key,this.value,this)),this.negated}}export class ContextKeyRegexExpr{constructor(e,t){this.key=e,this.regexp=t,this.type=7,this.negated=null}static create(e,t){return new ContextKeyRegexExpr(e,t)}cmp(e){if(e.type!==this.type)return this.type-e.type;if(this.key<e.key)return-1;if(this.key>e.key)return 1;const t=this.regexp?this.regexp.source:"",r=e.regexp?e.regexp.source:"";return t<r?-1:t>r?1:0}equals(e){if(e.type===this.type){const t=this.regexp?this.regexp.source:"",r=e.regexp?e.regexp.source:"";return this.key===e.key&&t===r}return!1}substituteConstants(){return this}evaluate(e){let t=e.getValue(this.key);return!!this.regexp&&this.regexp.test(t)}serialize(){const e=this.regexp?`/${this.regexp.source}/${this.regexp.ignoreCase?"i":""}`:"/invalid/";return`${this.key} =~ ${e}`}keys(){return[this.key]}negate(){return this.negated||(this.negated=ContextKeyNotRegexExpr.create(this)),this.negated}}export class ContextKeyNotRegexExpr{constructor(e){this._actual=e,this.type=8}static create(e){return new ContextKeyNotRegexExpr(e)}cmp(e){return e.type!==this.type?this.type-e.type:this._actual.cmp(e._actual)}equals(e){return e.type===this.type&&this._actual.equals(e._actual)}substituteConstants(){return this}evaluate(e){return!this._actual.evaluate(e)}serialize(){throw new Error("Method not implemented.")}keys(){return this._actual.keys()}negate(){return this._actual}}function eliminateConstantsInArray(e){let t=null;for(let r=0,s=e.length;r<s;r++){const s=e[r].substituteConstants();if(e[r]!==s&&null===t){t=[];for(let s=0;s<r;s++)t[s]=e[s]}null!==t&&(t[r]=s)}return null===t?e:t}class ContextKeyAndExpr{constructor(e,t){this.expr=e,this.negated=t,this.type=6}static create(e,t){return ContextKeyAndExpr._normalizeArr(e,t)}cmp(e){if(e.type!==this.type)return this.type-e.type;if(this.expr.length<e.expr.length)return-1;if(this.expr.length>e.expr.length)return 1;for(let t=0,r=this.expr.length;t<r;t++){const r=cmp(this.expr[t],e.expr[t]);if(0!==r)return r}return 0}equals(e){if(e.type===this.type){if(this.expr.length!==e.expr.length)return!1;for(let t=0,r=this.expr.length;t<r;t++)if(!this.expr[t].equals(e.expr[t]))return!1;return!0}return!1}substituteConstants(){const e=eliminateConstantsInArray(this.expr);return e===this.expr?this:ContextKeyAndExpr.create(e,this.negated)}evaluate(e){for(let t=0,r=this.expr.length;t<r;t++)if(!this.expr[t].evaluate(e))return!1;return!0}static _normalizeArr(e,t){const r=[];let s=!1;for(const n of e)if(n)if(1!==n.type){if(0===n.type)return ContextKeyFalseExpr.INSTANCE;6!==n.type?r.push(n):r.push(...n.expr)}else s=!0;if(0===r.length&&s)return ContextKeyTrueExpr.INSTANCE;if(0!==r.length){if(1===r.length)return r[0];r.sort(cmp);for(let e=1;e<r.length;e++)r[e-1].equals(r[e])&&(r.splice(e,1),e--);if(1===r.length)return r[0];while(r.length>1){const e=r[r.length-1];if(9!==e.type)break;r.pop();const t=r.pop(),s=0===r.length,n=ContextKeyOrExpr.create(e.expr.map((e=>ContextKeyAndExpr.create([e,t],null))),null,s);n&&(r.push(n),r.sort(cmp))}return 1===r.length?r[0]:new ContextKeyAndExpr(r,t)}}serialize(){return this.expr.map((e=>e.serialize())).join(" && ")}keys(){const e=[];for(let t of this.expr)e.push(...t.keys());return e}negate(){if(!this.negated){const e=[];for(let t of this.expr)e.push(t.negate());this.negated=ContextKeyOrExpr.create(e,this,!0)}return this.negated}}class ContextKeyOrExpr{constructor(e,t){this.expr=e,this.negated=t,this.type=9}static create(e,t,r){return ContextKeyOrExpr._normalizeArr(e,t,r)}cmp(e){if(e.type!==this.type)return this.type-e.type;if(this.expr.length<e.expr.length)return-1;if(this.expr.length>e.expr.length)return 1;for(let t=0,r=this.expr.length;t<r;t++){const r=cmp(this.expr[t],e.expr[t]);if(0!==r)return r}return 0}equals(e){if(e.type===this.type){if(this.expr.length!==e.expr.length)return!1;for(let t=0,r=this.expr.length;t<r;t++)if(!this.expr[t].equals(e.expr[t]))return!1;return!0}return!1}substituteConstants(){const e=eliminateConstantsInArray(this.expr);return e===this.expr?this:ContextKeyOrExpr.create(e,this.negated,!1)}evaluate(e){for(let t=0,r=this.expr.length;t<r;t++)if(this.expr[t].evaluate(e))return!0;return!1}static _normalizeArr(e,t,r){let s=[],n=!1;if(e){for(let t=0,r=e.length;t<r;t++){const r=e[t];if(r)if(0!==r.type){if(1===r.type)return ContextKeyTrueExpr.INSTANCE;9!==r.type?s.push(r):s=s.concat(r.expr)}else n=!0}if(0===s.length&&n)return ContextKeyFalseExpr.INSTANCE;s.sort(cmp)}if(0!==s.length){if(1===s.length)return s[0];for(let e=1;e<s.length;e++)s[e-1].equals(s[e])&&(s.splice(e,1),e--);if(1===s.length)return s[0];if(r){for(let e=0;e<s.length;e++)for(let t=e+1;t<s.length;t++)implies(s[e],s[t])&&(s.splice(t,1),t--);if(1===s.length)return s[0]}return new ContextKeyOrExpr(s,t)}}serialize(){return this.expr.map((e=>e.serialize())).join(" || ")}keys(){const e=[];for(let t of this.expr)e.push(...t.keys());return e}negate(){if(!this.negated){let e=[];for(let t of this.expr)e.push(t.negate());while(e.length>1){const t=e.shift(),r=e.shift(),s=[];for(const e of getTerminals(t))for(const t of getTerminals(r))s.push(ContextKeyAndExpr.create([e,t],null));const n=0===e.length;e.unshift(ContextKeyOrExpr.create(s,null,n))}this.negated=e[0]}return this.negated}}export class RawContextKey extends ContextKeyDefinedExpr{constructor(e,t,r){super(e,null),this._defaultValue=t,"object"===typeof r?RawContextKey._info.push(Object.assign(Object.assign({},r),{key:e})):!0!==r&&RawContextKey._info.push({key:e,description:r,type:null!==t&&void 0!==t?typeof t:void 0})}static all(){return RawContextKey._info.values()}bindTo(e){return e.createKey(this.key,this._defaultValue)}getValue(e){return e.getContextKeyValue(this.key)}toNegated(){return this.negate()}isEqualTo(e){return ContextKeyEqualsExpr.create(this.key,e)}}RawContextKey._info=[];export const IContextKeyService=createDecorator("contextKeyService");export const SET_CONTEXT_COMMAND_ID="setContext";function cmp1(e,t){return e<t?-1:e>t?1:0}function cmp2(e,t,r,s){return e<r?-1:e>r?1:t<s?-1:t>s?1:0}export function implies(e,t){if(6===t.type&&9!==e.type&&6!==e.type)for(const n of t.expr)if(e.equals(n))return!0;const r=e.negate(),s=getTerminals(r).concat(getTerminals(t));s.sort(cmp);for(let n=0;n<s.length;n++){const e=s[n],t=e.negate();for(let r=n+1;r<s.length;r++){const e=s[r];if(t.equals(e))return!0}}return!1}function getTerminals(e){return 9===e.type?e.expr:[e]}