import{createKeybinding}from"../../../base/common/keybindings.js";import{OS}from"../../../base/common/platform.js";import{CommandsRegistry}from"../../commands/common/commands.js";import{Registry}from"../../registry/common/platform.js";class KeybindingsRegistryImpl{constructor(){this._coreKeybindings=[],this._extensionKeybindings=[],this._cachedMergedKeybindings=null}static bindToCurrentPlatform(e){if(1===OS){if(e&&e.win)return e.win}else if(2===OS){if(e&&e.mac)return e.mac}else if(e&&e.linux)return e.linux;return e}registerKeybindingRule(e){const i=KeybindingsRegistryImpl.bindToCurrentPlatform(e);if(i&&i.primary){const n=createKeybinding(i.primary,OS);n&&this._registerDefaultKeybinding(n,e.id,e.args,e.weight,0,e.when)}if(i&&Array.isArray(i.secondary))for(let n=0,t=i.secondary.length;n<t;n++){const t=i.secondary[n],r=createKeybinding(t,OS);r&&this._registerDefaultKeybinding(r,e.id,e.args,e.weight,-n-1,e.when)}}registerCommandAndKeybindingRule(e){this.registerKeybindingRule(e),CommandsRegistry.registerCommand(e)}static _mightProduceChar(e){return e>=21&&e<=30||(e>=31&&e<=56||(80===e||81===e||82===e||83===e||84===e||85===e||86===e||110===e||111===e||87===e||88===e||89===e||90===e||91===e||92===e))}_assertNoCtrlAlt(e,i){e.ctrlKey&&e.altKey&&!e.metaKey&&KeybindingsRegistryImpl._mightProduceChar(e.keyCode)&&console.warn("Ctrl+Alt+ keybindings should not be used by default under Windows. Offender: ",e," for ",i)}_registerDefaultKeybinding(e,i,n,t,r,s){1===OS&&this._assertNoCtrlAlt(e.parts[0],i),this._coreKeybindings.push({keybinding:e.parts,command:i,commandArgs:n,when:s,weight1:t,weight2:r,extensionId:null,isBuiltinExtension:!1}),this._cachedMergedKeybindings=null}getDefaultKeybindings(){return this._cachedMergedKeybindings||(this._cachedMergedKeybindings=[].concat(this._coreKeybindings).concat(this._extensionKeybindings),this._cachedMergedKeybindings.sort(sorter)),this._cachedMergedKeybindings.slice(0)}}export const KeybindingsRegistry=new KeybindingsRegistryImpl;export const Extensions={EditorModes:"platform.keybindingsRegistry"};function sorter(e,i){return e.weight1!==i.weight1?e.weight1-i.weight1:e.command<i.command?-1:e.command>i.command?1:e.weight2-i.weight2}Registry.add(Extensions.EditorModes,KeybindingsRegistry);