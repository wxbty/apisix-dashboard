var __decorate=this&&this.__decorate||function(e,t,i,s){var o,n=arguments.length,r=n<3?t:null===s?s=Object.getOwnPropertyDescriptor(t,i):s;if("object"===typeof Reflect&&"function"===typeof Reflect.decorate)r=Reflect.decorate(e,t,i,s);else for(var h=e.length-1;h>=0;h--)(o=e[h])&&(r=(n<3?o(r):n>3?o(t,i,r):o(t,i))||r);return n>3&&r&&Object.defineProperty(t,i,r),r},__param=this&&this.__param||function(e,t){return function(i,s){t(i,s,e)}};import{IContextKeyService,RawContextKey}from"../../../../platform/contextkey/common/contextkey.js";let SuggestAlternatives=class e{constructor(t,i){this._editor=t,this._index=0,this._ckOtherSuggestions=e.OtherSuggestions.bindTo(i)}dispose(){this.reset()}reset(){var e;this._ckOtherSuggestions.reset(),null===(e=this._listener)||void 0===e||e.dispose(),this._model=void 0,this._acceptNext=void 0,this._ignore=!1}set({model:t,index:i},s){if(0===t.items.length)return void this.reset();let o=e._moveIndex(!0,t,i);o!==i?(this._acceptNext=s,this._model=t,this._index=i,this._listener=this._editor.onDidChangeCursorPosition((()=>{this._ignore||this.reset()})),this._ckOtherSuggestions.set(!0)):this.reset()}static _moveIndex(e,t,i){let s=i;while(1){if(s=(s+t.items.length+(e?1:-1))%t.items.length,s===i)break;if(!t.items[s].completion.additionalTextEdits)break}return s}next(){this._move(!0)}prev(){this._move(!1)}_move(t){if(this._model)try{this._ignore=!0,this._index=e._moveIndex(t,this._model,this._index),this._acceptNext({index:this._index,item:this._model.items[this._index],model:this._model})}finally{this._ignore=!1}}};SuggestAlternatives.OtherSuggestions=new RawContextKey("hasOtherSuggestions",!1),SuggestAlternatives=__decorate([__param(1,IContextKeyService)],SuggestAlternatives);export{SuggestAlternatives};