import{CancellationTokenSource}from"../../../base/common/cancellation.js";import{Emitter}from"../../../base/common/event.js";import{KeyChord}from"../../../base/common/keyCodes.js";import{URI}from"../../../base/common/uri.js";import{Position}from"../core/position.js";import{Range}from"../core/range.js";import{Selection}from"../core/selection.js";import{Token}from"../languages.js";import*as standaloneEnums from"../standalone/standaloneEnums.js";export class KeyMod{static chord(o,e){return KeyChord(o,e)}}KeyMod.CtrlCmd=2048,KeyMod.Shift=1024,KeyMod.Alt=512,KeyMod.WinCtrl=256;export function createMonacoBaseAPI(){return{editor:void 0,languages:void 0,CancellationTokenSource:CancellationTokenSource,Emitter:Emitter,KeyCode:standaloneEnums.KeyCode,KeyMod:KeyMod,Position:Position,Range:Range,Selection:Selection,SelectionDirection:standaloneEnums.SelectionDirection,MarkerSeverity:standaloneEnums.MarkerSeverity,MarkerTag:standaloneEnums.MarkerTag,Uri:URI,Token:Token}}