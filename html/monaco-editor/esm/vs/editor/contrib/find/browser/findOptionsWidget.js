import*as dom from"../../../../base/browser/dom.js";import{CaseSensitiveCheckbox,RegexCheckbox,WholeWordsCheckbox}from"../../../../base/browser/ui/findinput/findInputCheckboxes.js";import{Widget}from"../../../../base/browser/ui/widget.js";import{RunOnceScheduler}from"../../../../base/common/async.js";import{FIND_IDS}from"./findModel.js";import{contrastBorder,editorWidgetBackground,editorWidgetForeground,inputActiveOptionBackground,inputActiveOptionBorder,inputActiveOptionForeground,widgetShadow}from"../../../../platform/theme/common/colorRegistry.js";import{registerThemingParticipant}from"../../../../platform/theme/common/themeService.js";export class FindOptionsWidget extends Widget{constructor(e,t,i,o){super(),this._hideSoon=this._register(new RunOnceScheduler((()=>this._hide()),2e3)),this._isVisible=!1,this._editor=e,this._state=t,this._keybindingService=i,this._domNode=document.createElement("div"),this._domNode.className="findOptionsWidget",this._domNode.style.display="none",this._domNode.style.top="10px",this._domNode.setAttribute("role","presentation"),this._domNode.setAttribute("aria-hidden","true");const s=o.getColorTheme().getColor(inputActiveOptionBorder),r=o.getColorTheme().getColor(inputActiveOptionForeground),d=o.getColorTheme().getColor(inputActiveOptionBackground);this.caseSensitive=this._register(new CaseSensitiveCheckbox({appendTitle:this._keybindingLabelFor(FIND_IDS.ToggleCaseSensitiveCommand),isChecked:this._state.matchCase,inputActiveOptionBorder:s,inputActiveOptionForeground:r,inputActiveOptionBackground:d})),this._domNode.appendChild(this.caseSensitive.domNode),this._register(this.caseSensitive.onChange((()=>{this._state.change({matchCase:this.caseSensitive.checked},!1)}))),this.wholeWords=this._register(new WholeWordsCheckbox({appendTitle:this._keybindingLabelFor(FIND_IDS.ToggleWholeWordCommand),isChecked:this._state.wholeWord,inputActiveOptionBorder:s,inputActiveOptionForeground:r,inputActiveOptionBackground:d})),this._domNode.appendChild(this.wholeWords.domNode),this._register(this.wholeWords.onChange((()=>{this._state.change({wholeWord:this.wholeWords.checked},!1)}))),this.regex=this._register(new RegexCheckbox({appendTitle:this._keybindingLabelFor(FIND_IDS.ToggleRegexCommand),isChecked:this._state.isRegex,inputActiveOptionBorder:s,inputActiveOptionForeground:r,inputActiveOptionBackground:d})),this._domNode.appendChild(this.regex.domNode),this._register(this.regex.onChange((()=>{this._state.change({isRegex:this.regex.checked},!1)}))),this._editor.addOverlayWidget(this),this._register(this._state.onFindReplaceStateChange((e=>{let t=!1;e.isRegex&&(this.regex.checked=this._state.isRegex,t=!0),e.wholeWord&&(this.wholeWords.checked=this._state.wholeWord,t=!0),e.matchCase&&(this.caseSensitive.checked=this._state.matchCase,t=!0),!this._state.isRevealed&&t&&this._revealTemporarily()}))),this._register(dom.addDisposableNonBubblingMouseOutListener(this._domNode,(e=>this._onMouseOut()))),this._register(dom.addDisposableListener(this._domNode,"mouseover",(e=>this._onMouseOver()))),this._applyTheme(o.getColorTheme()),this._register(o.onDidColorThemeChange(this._applyTheme.bind(this)))}_keybindingLabelFor(e){let t=this._keybindingService.lookupKeybinding(e);return t?` (${t.getLabel()})`:""}dispose(){this._editor.removeOverlayWidget(this),super.dispose()}getId(){return FindOptionsWidget.ID}getDomNode(){return this._domNode}getPosition(){return{preference:0}}highlightFindOptions(){this._revealTemporarily()}_revealTemporarily(){this._show(),this._hideSoon.schedule()}_onMouseOut(){this._hideSoon.schedule()}_onMouseOver(){this._hideSoon.cancel()}_show(){this._isVisible||(this._isVisible=!0,this._domNode.style.display="block")}_hide(){this._isVisible&&(this._isVisible=!1,this._domNode.style.display="none")}_applyTheme(e){let t={inputActiveOptionBorder:e.getColor(inputActiveOptionBorder),inputActiveOptionForeground:e.getColor(inputActiveOptionForeground),inputActiveOptionBackground:e.getColor(inputActiveOptionBackground)};this.caseSensitive.style(t),this.wholeWords.style(t),this.regex.style(t)}}FindOptionsWidget.ID="editor.contrib.findOptionsWidget",registerThemingParticipant(((e,t)=>{const i=e.getColor(editorWidgetBackground);i&&t.addRule(`.monaco-editor .findOptionsWidget { background-color: ${i}; }`);const o=e.getColor(editorWidgetForeground);o&&t.addRule(`.monaco-editor .findOptionsWidget { color: ${o}; }`);const s=e.getColor(widgetShadow);s&&t.addRule(`.monaco-editor .findOptionsWidget { box-shadow: 0 0 8px 2px ${s}; }`);const r=e.getColor(contrastBorder);r&&t.addRule(`.monaco-editor .findOptionsWidget { border: 2px solid ${r}; }`)}));