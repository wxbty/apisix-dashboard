import{StandardWheelEvent}from"../../mouseEvent.js";import{AbstractScrollbar}from"./abstractScrollbar.js";import{ARROW_IMG_SIZE}from"./scrollbarArrow.js";import{ScrollbarState}from"./scrollbarState.js";import{Codicon}from"../../../common/codicons.js";export class VerticalScrollbar extends AbstractScrollbar{constructor(e,r,t){const o=e.getScrollDimensions(),l=e.getCurrentScrollPosition();if(super({lazyRender:r.lazyRender,host:t,scrollbarState:new ScrollbarState(r.verticalHasArrows?r.arrowSize:0,2===r.vertical?0:r.verticalScrollbarSize,0,o.height,o.scrollHeight,l.scrollTop),visibility:r.vertical,extraScrollbarClassName:"vertical",scrollable:e,scrollByPage:r.scrollByPage}),r.verticalHasArrows){const e=(r.arrowSize-ARROW_IMG_SIZE)/2,t=(r.verticalScrollbarSize-ARROW_IMG_SIZE)/2;this._createArrow({className:"scra",icon:Codicon.scrollbarButtonUp,top:e,left:t,bottom:void 0,right:void 0,bgWidth:r.verticalScrollbarSize,bgHeight:r.arrowSize,onActivate:()=>this._host.onMouseWheel(new StandardWheelEvent(null,0,1))}),this._createArrow({className:"scra",icon:Codicon.scrollbarButtonDown,top:void 0,left:t,bottom:e,right:void 0,bgWidth:r.verticalScrollbarSize,bgHeight:r.arrowSize,onActivate:()=>this._host.onMouseWheel(new StandardWheelEvent(null,0,-1))})}this._createSlider(0,Math.floor((r.verticalScrollbarSize-r.verticalSliderSize)/2),r.verticalSliderSize,void 0)}_updateSlider(e,r){this.slider.setHeight(e),this.slider.setTop(r)}_renderDomNode(e,r){this.domNode.setWidth(r),this.domNode.setHeight(e),this.domNode.setRight(0),this.domNode.setTop(0)}onDidScroll(e){return this._shouldRender=this._onElementScrollSize(e.scrollHeight)||this._shouldRender,this._shouldRender=this._onElementScrollPosition(e.scrollTop)||this._shouldRender,this._shouldRender=this._onElementSize(e.height)||this._shouldRender,this._shouldRender}_mouseDownRelativePosition(e,r){return r}_sliderMousePosition(e){return e.posy}_sliderOrthogonalMousePosition(e){return e.posx}_updateScrollbarSize(e){this.slider.setWidth(e)}writeScrollPosition(e,r){e.scrollTop=r}updateOptions(e){this.updateScrollbarSize(2===e.vertical?0:e.verticalScrollbarSize),this._scrollbarState.setOppositeScrollbarSize(0),this._visibilityController.setVisibility(e.vertical),this._scrollByPage=e.scrollByPage}}