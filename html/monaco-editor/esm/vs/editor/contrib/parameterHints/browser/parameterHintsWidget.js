var __decorate=this&&this.__decorate||function(e,t,o,r){var i,s=arguments.length,n=s<3?t:null===r?r=Object.getOwnPropertyDescriptor(t,o):r;if("object"===typeof Reflect&&"function"===typeof Reflect.decorate)n=Reflect.decorate(e,t,o,r);else for(var a=e.length-1;a>=0;a--)(i=e[a])&&(n=(s<3?i(n):s>3?i(t,o,n):i(t,o))||n);return s>3&&n&&Object.defineProperty(t,o,n),n},__param=this&&this.__param||function(e,t){return function(o,r){t(o,r,e)}};import*as dom from"../../../../base/browser/dom.js";import*as aria from"../../../../base/browser/ui/aria/aria.js";import{DomScrollableElement}from"../../../../base/browser/ui/scrollbar/scrollableElement.js";import{Codicon}from"../../../../base/common/codicons.js";import{Event}from"../../../../base/common/event.js";import{Disposable,DisposableStore}from"../../../../base/common/lifecycle.js";import{escapeRegExpCharacters}from"../../../../base/common/strings.js";import{assertIsDefined}from"../../../../base/common/types.js";import"./parameterHints.css";import{MarkdownRenderer}from"../../markdownRenderer/browser/markdownRenderer.js";import{ILanguageService}from"../../../common/services/language.js";import{ParameterHintsModel}from"./parameterHintsModel.js";import{Context}from"./provideSignatureHelp.js";import*as nls from"../../../../nls.js";import{IContextKeyService}from"../../../../platform/contextkey/common/contextkey.js";import{IOpenerService}from"../../../../platform/opener/common/opener.js";import{editorHoverBackground,editorHoverBorder,editorHoverForeground,registerColor,textCodeBlockBackground,textLinkActiveForeground,textLinkForeground,listHighlightForeground}from"../../../../platform/theme/common/colorRegistry.js";import{registerIcon}from"../../../../platform/theme/common/iconRegistry.js";import{ColorScheme}from"../../../../platform/theme/common/theme.js";import{registerThemingParticipant,ThemeIcon}from"../../../../platform/theme/common/themeService.js";const $=dom.$,parameterHintsNextIcon=registerIcon("parameter-hints-next",Codicon.chevronDown,nls.localize("parameterHintsNextIcon","Icon for show next parameter hint.")),parameterHintsPreviousIcon=registerIcon("parameter-hints-previous",Codicon.chevronUp,nls.localize("parameterHintsPreviousIcon","Icon for show previous parameter hint."));let ParameterHintsWidget=class e extends Disposable{constructor(e,t,o,r){super(),this.editor=e,this.renderDisposeables=this._register(new DisposableStore),this.visible=!1,this.announcedLabel=null,this.allowEditorOverflow=!0,this.markdownRenderer=this._register(new MarkdownRenderer({editor:e},r,o)),this.model=this._register(new ParameterHintsModel(e)),this.keyVisible=Context.Visible.bindTo(t),this.keyMultipleSignatures=Context.MultipleSignatures.bindTo(t),this._register(this.model.onChangedHints((e=>{e?(this.show(),this.render(e)):this.hide()})))}createParameterHintDOMNodes(){const e=$(".editor-widget.parameter-hints-widget"),t=dom.append(e,$(".phwrapper"));t.tabIndex=-1;const o=dom.append(t,$(".controls")),r=dom.append(o,$(".button"+ThemeIcon.asCSSSelector(parameterHintsPreviousIcon))),i=dom.append(o,$(".overloads")),s=dom.append(o,$(".button"+ThemeIcon.asCSSSelector(parameterHintsNextIcon)));this._register(dom.addDisposableListener(r,"click",(e=>{dom.EventHelper.stop(e),this.previous()}))),this._register(dom.addDisposableListener(s,"click",(e=>{dom.EventHelper.stop(e),this.next()})));const n=$(".body"),a=new DomScrollableElement(n,{});this._register(a),t.appendChild(a.getDomNode());const d=dom.append(n,$(".signature")),l=dom.append(n,$(".docs"));e.style.userSelect="text",this.domNodes={element:e,signature:d,overloads:i,docs:l,scrollbar:a},this.editor.addContentWidget(this),this.hide(),this._register(this.editor.onDidChangeCursorSelection((e=>{this.visible&&this.editor.layoutContentWidget(this)})));const m=()=>{if(!this.domNodes)return;const e=this.editor.getOption(44);this.domNodes.element.style.fontSize=`${e.fontSize}px`,this.domNodes.element.style.lineHeight=""+e.lineHeight/e.fontSize};m(),this._register(Event.chain(this.editor.onDidChangeConfiguration.bind(this.editor)).filter((e=>e.hasChanged(44))).on(m,null)),this._register(this.editor.onDidLayoutChange((e=>this.updateMaxHeight()))),this.updateMaxHeight()}show(){this.visible||(this.domNodes||this.createParameterHintDOMNodes(),this.keyVisible.set(!0),this.visible=!0,setTimeout((()=>{this.domNodes&&this.domNodes.element.classList.add("visible")}),100),this.editor.layoutContentWidget(this))}hide(){this.renderDisposeables.clear(),this.visible&&(this.keyVisible.reset(),this.visible=!1,this.announcedLabel=null,this.domNodes&&this.domNodes.element.classList.remove("visible"),this.editor.layoutContentWidget(this))}getPosition(){return this.visible?{position:this.editor.getPosition(),preference:[1,2]}:null}render(e){var t;if(this.renderDisposeables.clear(),!this.domNodes)return;const o=e.signatures.length>1;this.domNodes.element.classList.toggle("multiple",o),this.keyMultipleSignatures.set(o),this.domNodes.signature.innerText="",this.domNodes.docs.innerText="";const r=e.signatures[e.activeSignature];if(!r)return;const i=dom.append(this.domNodes.signature,$(".code")),s=this.editor.getOption(44);i.style.fontSize=`${s.fontSize}px`,i.style.fontFamily=s.fontFamily;const n=r.parameters.length>0,a=null!==(t=r.activeParameter)&&void 0!==t?t:e.activeParameter;if(n)this.renderParameters(i,r,a);else{const e=dom.append(i,$("span"));e.textContent=r.label}const d=r.parameters[a];if(null===d||void 0===d?void 0:d.documentation){const e=$("span.documentation");if("string"===typeof d.documentation)e.textContent=d.documentation;else{const t=this.renderMarkdownDocs(d.documentation);e.appendChild(t.element)}dom.append(this.domNodes.docs,$("p",{},e))}if(void 0===r.documentation);else if("string"===typeof r.documentation)dom.append(this.domNodes.docs,$("p",{},r.documentation));else{const e=this.renderMarkdownDocs(r.documentation);dom.append(this.domNodes.docs,e.element)}const l=this.hasDocs(r,d);if(this.domNodes.signature.classList.toggle("has-docs",l),this.domNodes.docs.classList.toggle("empty",!l),this.domNodes.overloads.textContent=String(e.activeSignature+1).padStart(e.signatures.length.toString().length,"0")+"/"+e.signatures.length,d){let e="";const t=r.parameters[a];e=Array.isArray(t.label)?r.label.substring(t.label[0],t.label[1]):t.label,t.documentation&&(e+="string"===typeof t.documentation?`, ${t.documentation}`:`, ${t.documentation.value}`),r.documentation&&(e+="string"===typeof r.documentation?`, ${r.documentation}`:`, ${r.documentation.value}`),this.announcedLabel!==e&&(aria.alert(nls.localize("hint","{0}, hint",e)),this.announcedLabel=e)}this.editor.layoutContentWidget(this),this.domNodes.scrollbar.scanDomNode()}renderMarkdownDocs(e){const t=this.renderDisposeables.add(this.markdownRenderer.render(e,{asyncRenderCallback:()=>{var e;null===(e=this.domNodes)||void 0===e||e.scrollbar.scanDomNode()}}));return t.element.classList.add("markdown-docs"),t}hasDocs(e,t){return!!(t&&"string"===typeof t.documentation&&assertIsDefined(t.documentation).length>0)||(!!(t&&"object"===typeof t.documentation&&assertIsDefined(t.documentation).value.length>0)||(!!(e.documentation&&"string"===typeof e.documentation&&assertIsDefined(e.documentation).length>0)||!!(e.documentation&&"object"===typeof e.documentation&&assertIsDefined(e.documentation.value).length>0)))}renderParameters(e,t,o){const[r,i]=this.getParameterLabelOffsets(t,o),s=document.createElement("span");s.textContent=t.label.substring(0,r);const n=document.createElement("span");n.textContent=t.label.substring(r,i),n.className="parameter active";const a=document.createElement("span");a.textContent=t.label.substring(i),dom.append(e,s,n,a)}getParameterLabelOffsets(e,t){const o=e.parameters[t];if(o){if(Array.isArray(o.label))return o.label;if(o.label.length){const t=new RegExp(`(\\W|^)${escapeRegExpCharacters(o.label)}(?=\\W|$)`,"g");t.test(e.label);const r=t.lastIndex-o.label.length;return r>=0?[r,t.lastIndex]:[0,0]}return[0,0]}return[0,0]}next(){this.editor.focus(),this.model.next()}previous(){this.editor.focus(),this.model.previous()}cancel(){this.model.cancel()}getDomNode(){return this.domNodes||this.createParameterHintDOMNodes(),this.domNodes.element}getId(){return e.ID}trigger(e){this.model.trigger(e,0)}updateMaxHeight(){if(!this.domNodes)return;const e=Math.max(this.editor.getLayoutInfo().height/4,250),t=`${e}px`;this.domNodes.element.style.maxHeight=t;const o=this.domNodes.element.getElementsByClassName("phwrapper");o.length&&(o[0].style.maxHeight=t)}};ParameterHintsWidget.ID="editor.widget.parameterHintsWidget",ParameterHintsWidget=__decorate([__param(1,IContextKeyService),__param(2,IOpenerService),__param(3,ILanguageService)],ParameterHintsWidget);export{ParameterHintsWidget};export const editorHoverWidgetHighlightForeground=registerColor("editorHoverWidget.highlightForeground",{dark:listHighlightForeground,light:listHighlightForeground,hc:listHighlightForeground},nls.localize("editorHoverWidgetHighlightForeground","Foreground color of the active item in the parameter hint."));registerThemingParticipant(((e,t)=>{const o=e.getColor(editorHoverBorder);if(o){const r=e.type===ColorScheme.HIGH_CONTRAST?2:1;t.addRule(`.monaco-editor .parameter-hints-widget { border: ${r}px solid ${o}; }`),t.addRule(`.monaco-editor .parameter-hints-widget.multiple .body { border-left: 1px solid ${o.transparent(.5)}; }`),t.addRule(`.monaco-editor .parameter-hints-widget .signature.has-docs { border-bottom: 1px solid ${o.transparent(.5)}; }`)}const r=e.getColor(editorHoverBackground);r&&t.addRule(`.monaco-editor .parameter-hints-widget { background-color: ${r}; }`);const i=e.getColor(textLinkForeground);i&&t.addRule(`.monaco-editor .parameter-hints-widget a { color: ${i}; }`);const s=e.getColor(textLinkActiveForeground);s&&t.addRule(`.monaco-editor .parameter-hints-widget a:hover { color: ${s}; }`);const n=e.getColor(editorHoverForeground);n&&t.addRule(`.monaco-editor .parameter-hints-widget { color: ${n}; }`);const a=e.getColor(textCodeBlockBackground);a&&t.addRule(`.monaco-editor .parameter-hints-widget code { background-color: ${a}; }`);const d=e.getColor(editorHoverWidgetHighlightForeground);d&&t.addRule(`.monaco-editor .parameter-hints-widget .parameter.active { color: ${d}}`)}));