import*as dom from"../../dom.js";import{CaseSensitiveCheckbox,RegexCheckbox,WholeWordsCheckbox}from"./findInputCheckboxes.js";import{HistoryInputBox}from"../inputbox/inputBox.js";import{Widget}from"../widget.js";import{Emitter}from"../../../common/event.js";import"./findInput.css";import*as nls from"../../../../nls.js";const NLS_DEFAULT_LABEL=nls.localize("defaultLabel","input");export class FindInput extends Widget{constructor(i,t,n,o){super(),this._showOptionButtons=n,this.fixFocusOnOptionClickEnabled=!0,this.imeSessionInProgress=!1,this._onDidOptionChange=this._register(new Emitter),this.onDidOptionChange=this._onDidOptionChange.event,this._onKeyDown=this._register(new Emitter),this.onKeyDown=this._onKeyDown.event,this._onMouseDown=this._register(new Emitter),this.onMouseDown=this._onMouseDown.event,this._onInput=this._register(new Emitter),this._onKeyUp=this._register(new Emitter),this._onCaseSensitiveKeyDown=this._register(new Emitter),this.onCaseSensitiveKeyDown=this._onCaseSensitiveKeyDown.event,this._onRegexKeyDown=this._register(new Emitter),this.onRegexKeyDown=this._onRegexKeyDown.event,this._lastHighlightFindOptions=0,this.contextViewProvider=t,this.placeholder=o.placeholder||"",this.validation=o.validation,this.label=o.label||NLS_DEFAULT_LABEL,this.inputActiveOptionBorder=o.inputActiveOptionBorder,this.inputActiveOptionForeground=o.inputActiveOptionForeground,this.inputActiveOptionBackground=o.inputActiveOptionBackground,this.inputBackground=o.inputBackground,this.inputForeground=o.inputForeground,this.inputBorder=o.inputBorder,this.inputValidationInfoBorder=o.inputValidationInfoBorder,this.inputValidationInfoBackground=o.inputValidationInfoBackground,this.inputValidationInfoForeground=o.inputValidationInfoForeground,this.inputValidationWarningBorder=o.inputValidationWarningBorder,this.inputValidationWarningBackground=o.inputValidationWarningBackground,this.inputValidationWarningForeground=o.inputValidationWarningForeground,this.inputValidationErrorBorder=o.inputValidationErrorBorder,this.inputValidationErrorBackground=o.inputValidationErrorBackground,this.inputValidationErrorForeground=o.inputValidationErrorForeground;const e=o.appendCaseSensitiveLabel||"",r=o.appendWholeWordsLabel||"",s=o.appendRegexLabel||"",d=o.history||[],a=!!o.flexibleHeight,h=!!o.flexibleWidth,u=o.flexibleMaxHeight;this.domNode=document.createElement("div"),this.domNode.classList.add("monaco-findInput"),this.inputBox=this._register(new HistoryInputBox(this.domNode,this.contextViewProvider,{placeholder:this.placeholder||"",ariaLabel:this.label||"",validationOptions:{validation:this.validation},inputBackground:this.inputBackground,inputForeground:this.inputForeground,inputBorder:this.inputBorder,inputValidationInfoBackground:this.inputValidationInfoBackground,inputValidationInfoForeground:this.inputValidationInfoForeground,inputValidationInfoBorder:this.inputValidationInfoBorder,inputValidationWarningBackground:this.inputValidationWarningBackground,inputValidationWarningForeground:this.inputValidationWarningForeground,inputValidationWarningBorder:this.inputValidationWarningBorder,inputValidationErrorBackground:this.inputValidationErrorBackground,inputValidationErrorForeground:this.inputValidationErrorForeground,inputValidationErrorBorder:this.inputValidationErrorBorder,history:d,showHistoryHint:o.showHistoryHint,flexibleHeight:a,flexibleWidth:h,flexibleMaxHeight:u})),this.regex=this._register(new RegexCheckbox({appendTitle:s,isChecked:!1,inputActiveOptionBorder:this.inputActiveOptionBorder,inputActiveOptionForeground:this.inputActiveOptionForeground,inputActiveOptionBackground:this.inputActiveOptionBackground})),this._register(this.regex.onChange((i=>{this._onDidOptionChange.fire(i),!i&&this.fixFocusOnOptionClickEnabled&&this.inputBox.focus(),this.validate()}))),this._register(this.regex.onKeyDown((i=>{this._onRegexKeyDown.fire(i)}))),this.wholeWords=this._register(new WholeWordsCheckbox({appendTitle:r,isChecked:!1,inputActiveOptionBorder:this.inputActiveOptionBorder,inputActiveOptionForeground:this.inputActiveOptionForeground,inputActiveOptionBackground:this.inputActiveOptionBackground})),this._register(this.wholeWords.onChange((i=>{this._onDidOptionChange.fire(i),!i&&this.fixFocusOnOptionClickEnabled&&this.inputBox.focus(),this.validate()}))),this.caseSensitive=this._register(new CaseSensitiveCheckbox({appendTitle:e,isChecked:!1,inputActiveOptionBorder:this.inputActiveOptionBorder,inputActiveOptionForeground:this.inputActiveOptionForeground,inputActiveOptionBackground:this.inputActiveOptionBackground})),this._register(this.caseSensitive.onChange((i=>{this._onDidOptionChange.fire(i),!i&&this.fixFocusOnOptionClickEnabled&&this.inputBox.focus(),this.validate()}))),this._register(this.caseSensitive.onKeyDown((i=>{this._onCaseSensitiveKeyDown.fire(i)}))),this._showOptionButtons&&(this.inputBox.paddingRight=this.caseSensitive.width()+this.wholeWords.width()+this.regex.width());let p=[this.caseSensitive.domNode,this.wholeWords.domNode,this.regex.domNode];this.onkeydown(this.domNode,(i=>{if(i.equals(15)||i.equals(17)||i.equals(9)){let t=p.indexOf(document.activeElement);if(t>=0){let n=-1;i.equals(17)?n=(t+1)%p.length:i.equals(15)&&(n=0===t?p.length-1:t-1),i.equals(9)?(p[t].blur(),this.inputBox.focus()):n>=0&&p[n].focus(),dom.EventHelper.stop(i,!0)}}})),this.controls=document.createElement("div"),this.controls.className="controls",this.controls.style.display=this._showOptionButtons?"block":"none",this.controls.appendChild(this.caseSensitive.domNode),this.controls.appendChild(this.wholeWords.domNode),this.controls.appendChild(this.regex.domNode),this.domNode.appendChild(this.controls),i&&i.appendChild(this.domNode),this._register(dom.addDisposableListener(this.inputBox.inputElement,"compositionstart",(i=>{this.imeSessionInProgress=!0}))),this._register(dom.addDisposableListener(this.inputBox.inputElement,"compositionend",(i=>{this.imeSessionInProgress=!1,this._onInput.fire()}))),this.onkeydown(this.inputBox.inputElement,(i=>this._onKeyDown.fire(i))),this.onkeyup(this.inputBox.inputElement,(i=>this._onKeyUp.fire(i))),this.oninput(this.inputBox.inputElement,(i=>this._onInput.fire())),this.onmousedown(this.inputBox.inputElement,(i=>this._onMouseDown.fire(i)))}enable(){this.domNode.classList.remove("disabled"),this.inputBox.enable(),this.regex.enable(),this.wholeWords.enable(),this.caseSensitive.enable()}disable(){this.domNode.classList.add("disabled"),this.inputBox.disable(),this.regex.disable(),this.wholeWords.disable(),this.caseSensitive.disable()}setFocusInputOnOptionClick(i){this.fixFocusOnOptionClickEnabled=i}setEnabled(i){i?this.enable():this.disable()}getValue(){return this.inputBox.value}setValue(i){this.inputBox.value!==i&&(this.inputBox.value=i)}style(i){this.inputActiveOptionBorder=i.inputActiveOptionBorder,this.inputActiveOptionForeground=i.inputActiveOptionForeground,this.inputActiveOptionBackground=i.inputActiveOptionBackground,this.inputBackground=i.inputBackground,this.inputForeground=i.inputForeground,this.inputBorder=i.inputBorder,this.inputValidationInfoBackground=i.inputValidationInfoBackground,this.inputValidationInfoForeground=i.inputValidationInfoForeground,this.inputValidationInfoBorder=i.inputValidationInfoBorder,this.inputValidationWarningBackground=i.inputValidationWarningBackground,this.inputValidationWarningForeground=i.inputValidationWarningForeground,this.inputValidationWarningBorder=i.inputValidationWarningBorder,this.inputValidationErrorBackground=i.inputValidationErrorBackground,this.inputValidationErrorForeground=i.inputValidationErrorForeground,this.inputValidationErrorBorder=i.inputValidationErrorBorder,this.applyStyles()}applyStyles(){if(this.domNode){const i={inputActiveOptionBorder:this.inputActiveOptionBorder,inputActiveOptionForeground:this.inputActiveOptionForeground,inputActiveOptionBackground:this.inputActiveOptionBackground};this.regex.style(i),this.wholeWords.style(i),this.caseSensitive.style(i);const t={inputBackground:this.inputBackground,inputForeground:this.inputForeground,inputBorder:this.inputBorder,inputValidationInfoBackground:this.inputValidationInfoBackground,inputValidationInfoForeground:this.inputValidationInfoForeground,inputValidationInfoBorder:this.inputValidationInfoBorder,inputValidationWarningBackground:this.inputValidationWarningBackground,inputValidationWarningForeground:this.inputValidationWarningForeground,inputValidationWarningBorder:this.inputValidationWarningBorder,inputValidationErrorBackground:this.inputValidationErrorBackground,inputValidationErrorForeground:this.inputValidationErrorForeground,inputValidationErrorBorder:this.inputValidationErrorBorder};this.inputBox.style(t)}}select(){this.inputBox.select()}focus(){this.inputBox.focus()}getCaseSensitive(){return this.caseSensitive.checked}setCaseSensitive(i){this.caseSensitive.checked=i}getWholeWords(){return this.wholeWords.checked}setWholeWords(i){this.wholeWords.checked=i}getRegex(){return this.regex.checked}setRegex(i){this.regex.checked=i,this.validate()}focusOnCaseSensitive(){this.caseSensitive.focus()}highlightFindOptions(){this.domNode.classList.remove("highlight-"+this._lastHighlightFindOptions),this._lastHighlightFindOptions=1-this._lastHighlightFindOptions,this.domNode.classList.add("highlight-"+this._lastHighlightFindOptions)}validate(){this.inputBox.validate()}clearMessage(){this.inputBox.hideMessage()}}