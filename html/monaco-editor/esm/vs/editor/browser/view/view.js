import*as dom from"../../../base/browser/dom.js";import{Selection}from"../../common/core/selection.js";import{createFastDomNode}from"../../../base/browser/fastDomNode.js";import{onUnexpectedError}from"../../../base/common/errors.js";import{PointerHandler}from"../controller/pointerHandler.js";import{TextAreaHandler}from"../controller/textAreaHandler.js";import{ViewController}from"./viewController.js";import{ViewUserInputEvents}from"./viewUserInputEvents.js";import{ContentViewOverlays,MarginViewOverlays}from"./viewOverlays.js";import{PartFingerprints}from"./viewPart.js";import{ViewContentWidgets}from"../viewParts/contentWidgets/contentWidgets.js";import{CurrentLineHighlightOverlay,CurrentLineMarginHighlightOverlay}from"../viewParts/currentLineHighlight/currentLineHighlight.js";import{DecorationsOverlay}from"../viewParts/decorations/decorations.js";import{EditorScrollbar}from"../viewParts/editorScrollbar/editorScrollbar.js";import{GlyphMarginOverlay}from"../viewParts/glyphMargin/glyphMargin.js";import{IndentGuidesOverlay}from"../viewParts/indentGuides/indentGuides.js";import{LineNumbersOverlay}from"../viewParts/lineNumbers/lineNumbers.js";import{ViewLines}from"../viewParts/lines/viewLines.js";import{LinesDecorationsOverlay}from"../viewParts/linesDecorations/linesDecorations.js";import{Margin}from"../viewParts/margin/margin.js";import{MarginViewLineDecorationsOverlay}from"../viewParts/marginDecorations/marginDecorations.js";import{Minimap}from"../viewParts/minimap/minimap.js";import{ViewOverlayWidgets}from"../viewParts/overlayWidgets/overlayWidgets.js";import{DecorationsOverviewRuler}from"../viewParts/overviewRuler/decorationsOverviewRuler.js";import{OverviewRuler}from"../viewParts/overviewRuler/overviewRuler.js";import{Rulers}from"../viewParts/rulers/rulers.js";import{ScrollDecorationViewPart}from"../viewParts/scrollDecoration/scrollDecoration.js";import{SelectionsOverlay}from"../viewParts/selections/selections.js";import{ViewCursors}from"../viewParts/viewCursors/viewCursors.js";import{ViewZones}from"../viewParts/viewZones/viewZones.js";import{Position}from"../../common/core/position.js";import{Range}from"../../common/core/range.js";import{RenderingContext}from"./renderingContext.js";import{ViewContext}from"../../common/viewModel/viewContext.js";import{ViewportData}from"../../common/viewLayout/viewLinesViewportData.js";import{ViewEventHandler}from"../../common/viewModel/viewEventHandler.js";import{getThemeTypeSelector}from"../../../platform/theme/common/themeService.js";import{PointerHandlerLastRenderData}from"../controller/mouseTarget.js";export class View extends ViewEventHandler{constructor(e,t,i,o,n,s){super(),this._selections=[new Selection(1,1,1,1)],this._renderAnimationFrame=null;const r=new ViewController(t,o,n,e);this._context=new ViewContext(t,i.getColorTheme(),o),this._context.addEventHandler(this),this._register(i.onDidColorThemeChange((e=>{this._context.theme.update(e),this._context.model.onDidColorThemeChange(),this.render(!0,!1)}))),this._viewParts=[],this._textAreaHandler=new TextAreaHandler(this._context,r,this._createTextAreaHandlerHelper()),this._viewParts.push(this._textAreaHandler),this._linesContent=createFastDomNode(document.createElement("div")),this._linesContent.setClassName("lines-content monaco-editor-background"),this._linesContent.setPosition("absolute"),this.domNode=createFastDomNode(document.createElement("div")),this.domNode.setClassName(this._getEditorClassName()),this.domNode.setAttribute("role","code"),this._overflowGuardContainer=createFastDomNode(document.createElement("div")),PartFingerprints.write(this._overflowGuardContainer,3),this._overflowGuardContainer.setClassName("overflow-guard"),this._scrollbar=new EditorScrollbar(this._context,this._linesContent,this.domNode,this._overflowGuardContainer),this._viewParts.push(this._scrollbar),this._viewLines=new ViewLines(this._context,this._linesContent),this._viewZones=new ViewZones(this._context),this._viewParts.push(this._viewZones);const a=new DecorationsOverviewRuler(this._context);this._viewParts.push(a);const d=new ScrollDecorationViewPart(this._context);this._viewParts.push(d);const l=new ContentViewOverlays(this._context);this._viewParts.push(l),l.addDynamicOverlay(new CurrentLineHighlightOverlay(this._context)),l.addDynamicOverlay(new SelectionsOverlay(this._context)),l.addDynamicOverlay(new IndentGuidesOverlay(this._context)),l.addDynamicOverlay(new DecorationsOverlay(this._context));const h=new MarginViewOverlays(this._context);this._viewParts.push(h),h.addDynamicOverlay(new CurrentLineMarginHighlightOverlay(this._context)),h.addDynamicOverlay(new GlyphMarginOverlay(this._context)),h.addDynamicOverlay(new MarginViewLineDecorationsOverlay(this._context)),h.addDynamicOverlay(new LinesDecorationsOverlay(this._context)),h.addDynamicOverlay(new LineNumbersOverlay(this._context));const c=new Margin(this._context);c.getDomNode().appendChild(this._viewZones.marginDomNode),c.getDomNode().appendChild(h.getDomNode()),this._viewParts.push(c),this._contentWidgets=new ViewContentWidgets(this._context,this.domNode),this._viewParts.push(this._contentWidgets),this._viewCursors=new ViewCursors(this._context),this._viewParts.push(this._viewCursors),this._overlayWidgets=new ViewOverlayWidgets(this._context),this._viewParts.push(this._overlayWidgets);const m=new Rulers(this._context);this._viewParts.push(m);const w=new Minimap(this._context);if(this._viewParts.push(w),a){const e=this._scrollbar.getOverviewRulerLayoutInfo();e.parent.insertBefore(a.getDomNode(),e.insertBefore)}this._linesContent.appendChild(l.getDomNode()),this._linesContent.appendChild(m.domNode),this._linesContent.appendChild(this._viewZones.domNode),this._linesContent.appendChild(this._viewLines.getDomNode()),this._linesContent.appendChild(this._contentWidgets.domNode),this._linesContent.appendChild(this._viewCursors.getDomNode()),this._overflowGuardContainer.appendChild(c.getDomNode()),this._overflowGuardContainer.appendChild(this._scrollbar.getDomNode()),this._overflowGuardContainer.appendChild(d.getDomNode()),this._overflowGuardContainer.appendChild(this._textAreaHandler.textArea),this._overflowGuardContainer.appendChild(this._textAreaHandler.textAreaCover),this._overflowGuardContainer.appendChild(this._overlayWidgets.getDomNode()),this._overflowGuardContainer.appendChild(w.getDomNode()),this.domNode.appendChild(this._overflowGuardContainer),s?s.appendChild(this._contentWidgets.overflowingContentWidgetsDomNode.domNode):this.domNode.appendChild(this._contentWidgets.overflowingContentWidgetsDomNode),this._applyLayout(),this._pointerHandler=this._register(new PointerHandler(this._context,r,this._createPointerHandlerHelper()))}_flushAccumulatedAndRenderNow(){this._renderNow()}_createPointerHandlerHelper(){return{viewDomNode:this.domNode.domNode,linesContentDomNode:this._linesContent.domNode,focusTextArea:()=>{this.focus()},dispatchTextAreaEvent:e=>{this._textAreaHandler.textArea.domNode.dispatchEvent(e)},getLastRenderData:()=>{const e=this._viewCursors.getLastRenderData()||[],t=this._textAreaHandler.getLastRenderData();return new PointerHandlerLastRenderData(e,t)},shouldSuppressMouseDownOnViewZone:e=>this._viewZones.shouldSuppressMouseDownOnViewZone(e),shouldSuppressMouseDownOnWidget:e=>this._contentWidgets.shouldSuppressMouseDownOnWidget(e),getPositionFromDOMInfo:(e,t)=>(this._flushAccumulatedAndRenderNow(),this._viewLines.getPositionFromDOMInfo(e,t)),visibleRangeForPosition:(e,t)=>(this._flushAccumulatedAndRenderNow(),this._viewLines.visibleRangeForPosition(new Position(e,t))),getLineWidth:e=>(this._flushAccumulatedAndRenderNow(),this._viewLines.getLineWidth(e))}}_createTextAreaHandlerHelper(){return{visibleRangeForPosition:e=>(this._flushAccumulatedAndRenderNow(),this._viewLines.visibleRangeForPosition(e))}}_applyLayout(){const e=this._context.configuration.options,t=e.get(131);this.domNode.setWidth(t.width),this.domNode.setHeight(t.height),this._overflowGuardContainer.setWidth(t.width),this._overflowGuardContainer.setHeight(t.height),this._linesContent.setWidth(1e6),this._linesContent.setHeight(1e6)}_getEditorClassName(){const e=this._textAreaHandler.isFocused()?" focused":"";return this._context.configuration.options.get(128)+" "+getThemeTypeSelector(this._context.theme.type)+e}handleEvents(e){super.handleEvents(e),this._scheduleRender()}onConfigurationChanged(e){return this.domNode.setClassName(this._getEditorClassName()),this._applyLayout(),!1}onCursorStateChanged(e){return this._selections=e.selections,!1}onFocusChanged(e){return this.domNode.setClassName(this._getEditorClassName()),!1}onThemeChanged(e){return this.domNode.setClassName(this._getEditorClassName()),!1}dispose(){null!==this._renderAnimationFrame&&(this._renderAnimationFrame.dispose(),this._renderAnimationFrame=null),this._contentWidgets.overflowingContentWidgetsDomNode.domNode.remove(),this._context.removeEventHandler(this),this._viewLines.dispose();for(const e of this._viewParts)e.dispose();super.dispose()}_scheduleRender(){null===this._renderAnimationFrame&&(this._renderAnimationFrame=dom.runAtThisOrScheduleAtNextAnimationFrame(this._onRenderScheduled.bind(this),100))}_onRenderScheduled(){this._renderAnimationFrame=null,this._flushAccumulatedAndRenderNow()}_renderNow(){safeInvokeNoArg((()=>this._actualRender()))}_getViewPartsToRender(){const e=[];let t=0;for(const i of this._viewParts)i.shouldRender()&&(e[t++]=i);return e}_actualRender(){if(!dom.isInDOM(this.domNode.domNode))return;let e=this._getViewPartsToRender();if(!this._viewLines.shouldRender()&&0===e.length)return;const t=this._context.viewLayout.getLinesViewportData();this._context.model.setViewport(t.startLineNumber,t.endLineNumber,t.centeredLineNumber);const i=new ViewportData(this._selections,t,this._context.viewLayout.getWhitespaceViewportData(),this._context.model);this._contentWidgets.shouldRender()&&this._contentWidgets.onBeforeRender(i),this._viewLines.shouldRender()&&(this._viewLines.renderText(i),this._viewLines.onDidRender(),e=this._getViewPartsToRender());const o=new RenderingContext(this._context.viewLayout,i,this._viewLines);for(const n of e)n.prepareRender(o);for(const n of e)n.render(o),n.onDidRender()}delegateVerticalScrollbarMouseDown(e){this._scrollbar.delegateVerticalScrollbarMouseDown(e)}restoreState(e){this._context.model.setScrollPosition({scrollTop:e.scrollTop},1),this._context.model.tokenizeViewport(),this._renderNow(),this._viewLines.updateLineWidths(),this._context.model.setScrollPosition({scrollLeft:e.scrollLeft},1)}getOffsetForColumn(e,t){const i=this._context.model.validateModelPosition({lineNumber:e,column:t}),o=this._context.model.coordinatesConverter.convertModelPositionToViewPosition(i);this._flushAccumulatedAndRenderNow();const n=this._viewLines.visibleRangeForPosition(new Position(o.lineNumber,o.column));return n?n.left:-1}getTargetAtClientPoint(e,t){const i=this._pointerHandler.getTargetAtClientPoint(e,t);return i?ViewUserInputEvents.convertViewToModelMouseTarget(i,this._context.model.coordinatesConverter):null}createOverviewRuler(e){return new OverviewRuler(this._context,e)}change(e){this._viewZones.changeViewZones(e),this._scheduleRender()}render(e,t){if(t){this._viewLines.forceShouldRender();for(const e of this._viewParts)e.forceShouldRender()}e?this._flushAccumulatedAndRenderNow():this._scheduleRender()}focus(){this._textAreaHandler.focusTextArea()}isFocused(){return this._textAreaHandler.isFocused()}setAriaOptions(e){this._textAreaHandler.setAriaOptions(e)}addContentWidget(e){this._contentWidgets.addWidget(e.widget),this.layoutContentWidget(e),this._scheduleRender()}layoutContentWidget(e){let t=e.position&&e.position.range||null;if(null===t){const i=e.position?e.position.position:null;null!==i&&(t=new Range(i.lineNumber,i.column,i.lineNumber,i.column))}const i=e.position?e.position.preference:null;this._contentWidgets.setWidgetPosition(e.widget,t,i),this._scheduleRender()}removeContentWidget(e){this._contentWidgets.removeWidget(e.widget),this._scheduleRender()}addOverlayWidget(e){this._overlayWidgets.addWidget(e.widget),this.layoutOverlayWidget(e),this._scheduleRender()}layoutOverlayWidget(e){const t=e.position?e.position.preference:null,i=this._overlayWidgets.setWidgetPosition(e.widget,t);i&&this._scheduleRender()}removeOverlayWidget(e){this._overlayWidgets.removeWidget(e.widget),this._scheduleRender()}}function safeInvokeNoArg(e){try{return e()}catch(t){onUnexpectedError(t)}}