class KeyCodeStrMap{constructor(){this._keyCodeToStr=[],this._strToKeyCode=Object.create(null)}define(e,_){this._keyCodeToStr[e]=_,this._strToKeyCode[_.toLowerCase()]=e}keyCodeToStr(e){return this._keyCodeToStr[e]}strToKeyCode(e){return this._strToKeyCode[e.toLowerCase()]||0}}const uiMap=new KeyCodeStrMap,userSettingsUSMap=new KeyCodeStrMap,userSettingsGeneralMap=new KeyCodeStrMap;export const EVENT_KEY_CODE_MAP=new Array(230);export const NATIVE_WINDOWS_KEY_CODE_TO_KEY_CODE={};const scanCodeIntToStr=[],scanCodeStrToInt=Object.create(null),scanCodeLowerCaseStrToInt=Object.create(null);export const IMMUTABLE_CODE_TO_KEY_CODE=[];export const IMMUTABLE_KEY_CODE_TO_CODE=[];for(let e=0;e<=193;e++)IMMUTABLE_CODE_TO_KEY_CODE[e]=-1;for(let e=0;e<=126;e++)IMMUTABLE_KEY_CODE_TO_CODE[e]=-1;(function(){const e="",_=[[0,1,0,"None",0,"unknown",0,"VK_UNKNOWN",e,e],[0,1,1,"Hyper",0,e,0,e,e,e],[0,1,2,"Super",0,e,0,e,e,e],[0,1,3,"Fn",0,e,0,e,e,e],[0,1,4,"FnLock",0,e,0,e,e,e],[0,1,5,"Suspend",0,e,0,e,e,e],[0,1,6,"Resume",0,e,0,e,e,e],[0,1,7,"Turbo",0,e,0,e,e,e],[0,1,8,"Sleep",0,e,0,"VK_SLEEP",e,e],[0,1,9,"WakeUp",0,e,0,e,e,e],[31,0,10,"KeyA",31,"A",65,"VK_A",e,e],[32,0,11,"KeyB",32,"B",66,"VK_B",e,e],[33,0,12,"KeyC",33,"C",67,"VK_C",e,e],[34,0,13,"KeyD",34,"D",68,"VK_D",e,e],[35,0,14,"KeyE",35,"E",69,"VK_E",e,e],[36,0,15,"KeyF",36,"F",70,"VK_F",e,e],[37,0,16,"KeyG",37,"G",71,"VK_G",e,e],[38,0,17,"KeyH",38,"H",72,"VK_H",e,e],[39,0,18,"KeyI",39,"I",73,"VK_I",e,e],[40,0,19,"KeyJ",40,"J",74,"VK_J",e,e],[41,0,20,"KeyK",41,"K",75,"VK_K",e,e],[42,0,21,"KeyL",42,"L",76,"VK_L",e,e],[43,0,22,"KeyM",43,"M",77,"VK_M",e,e],[44,0,23,"KeyN",44,"N",78,"VK_N",e,e],[45,0,24,"KeyO",45,"O",79,"VK_O",e,e],[46,0,25,"KeyP",46,"P",80,"VK_P",e,e],[47,0,26,"KeyQ",47,"Q",81,"VK_Q",e,e],[48,0,27,"KeyR",48,"R",82,"VK_R",e,e],[49,0,28,"KeyS",49,"S",83,"VK_S",e,e],[50,0,29,"KeyT",50,"T",84,"VK_T",e,e],[51,0,30,"KeyU",51,"U",85,"VK_U",e,e],[52,0,31,"KeyV",52,"V",86,"VK_V",e,e],[53,0,32,"KeyW",53,"W",87,"VK_W",e,e],[54,0,33,"KeyX",54,"X",88,"VK_X",e,e],[55,0,34,"KeyY",55,"Y",89,"VK_Y",e,e],[56,0,35,"KeyZ",56,"Z",90,"VK_Z",e,e],[22,0,36,"Digit1",22,"1",49,"VK_1",e,e],[23,0,37,"Digit2",23,"2",50,"VK_2",e,e],[24,0,38,"Digit3",24,"3",51,"VK_3",e,e],[25,0,39,"Digit4",25,"4",52,"VK_4",e,e],[26,0,40,"Digit5",26,"5",53,"VK_5",e,e],[27,0,41,"Digit6",27,"6",54,"VK_6",e,e],[28,0,42,"Digit7",28,"7",55,"VK_7",e,e],[29,0,43,"Digit8",29,"8",56,"VK_8",e,e],[30,0,44,"Digit9",30,"9",57,"VK_9",e,e],[21,0,45,"Digit0",21,"0",48,"VK_0",e,e],[3,1,46,"Enter",3,"Enter",13,"VK_RETURN",e,e],[9,1,47,"Escape",9,"Escape",27,"VK_ESCAPE",e,e],[1,1,48,"Backspace",1,"Backspace",8,"VK_BACK",e,e],[2,1,49,"Tab",2,"Tab",9,"VK_TAB",e,e],[10,1,50,"Space",10,"Space",32,"VK_SPACE",e,e],[83,0,51,"Minus",83,"-",189,"VK_OEM_MINUS","-","OEM_MINUS"],[81,0,52,"Equal",81,"=",187,"VK_OEM_PLUS","=","OEM_PLUS"],[87,0,53,"BracketLeft",87,"[",219,"VK_OEM_4","[","OEM_4"],[89,0,54,"BracketRight",89,"]",221,"VK_OEM_6","]","OEM_6"],[88,0,55,"Backslash",88,"\\",220,"VK_OEM_5","\\","OEM_5"],[0,0,56,"IntlHash",0,e,0,e,e,e],[80,0,57,"Semicolon",80,";",186,"VK_OEM_1",";","OEM_1"],[90,0,58,"Quote",90,"'",222,"VK_OEM_7","'","OEM_7"],[86,0,59,"Backquote",86,"`",192,"VK_OEM_3","`","OEM_3"],[82,0,60,"Comma",82,",",188,"VK_OEM_COMMA",",","OEM_COMMA"],[84,0,61,"Period",84,".",190,"VK_OEM_PERIOD",".","OEM_PERIOD"],[85,0,62,"Slash",85,"/",191,"VK_OEM_2","/","OEM_2"],[8,1,63,"CapsLock",8,"CapsLock",20,"VK_CAPITAL",e,e],[59,1,64,"F1",59,"F1",112,"VK_F1",e,e],[60,1,65,"F2",60,"F2",113,"VK_F2",e,e],[61,1,66,"F3",61,"F3",114,"VK_F3",e,e],[62,1,67,"F4",62,"F4",115,"VK_F4",e,e],[63,1,68,"F5",63,"F5",116,"VK_F5",e,e],[64,1,69,"F6",64,"F6",117,"VK_F6",e,e],[65,1,70,"F7",65,"F7",118,"VK_F7",e,e],[66,1,71,"F8",66,"F8",119,"VK_F8",e,e],[67,1,72,"F9",67,"F9",120,"VK_F9",e,e],[68,1,73,"F10",68,"F10",121,"VK_F10",e,e],[69,1,74,"F11",69,"F11",122,"VK_F11",e,e],[70,1,75,"F12",70,"F12",123,"VK_F12",e,e],[0,1,76,"PrintScreen",0,e,0,e,e,e],[79,1,77,"ScrollLock",79,"ScrollLock",145,"VK_SCROLL",e,e],[7,1,78,"Pause",7,"PauseBreak",19,"VK_PAUSE",e,e],[19,1,79,"Insert",19,"Insert",45,"VK_INSERT",e,e],[14,1,80,"Home",14,"Home",36,"VK_HOME",e,e],[11,1,81,"PageUp",11,"PageUp",33,"VK_PRIOR",e,e],[20,1,82,"Delete",20,"Delete",46,"VK_DELETE",e,e],[13,1,83,"End",13,"End",35,"VK_END",e,e],[12,1,84,"PageDown",12,"PageDown",34,"VK_NEXT",e,e],[17,1,85,"ArrowRight",17,"RightArrow",39,"VK_RIGHT","Right",e],[15,1,86,"ArrowLeft",15,"LeftArrow",37,"VK_LEFT","Left",e],[18,1,87,"ArrowDown",18,"DownArrow",40,"VK_DOWN","Down",e],[16,1,88,"ArrowUp",16,"UpArrow",38,"VK_UP","Up",e],[78,1,89,"NumLock",78,"NumLock",144,"VK_NUMLOCK",e,e],[108,1,90,"NumpadDivide",108,"NumPad_Divide",111,"VK_DIVIDE",e,e],[103,1,91,"NumpadMultiply",103,"NumPad_Multiply",106,"VK_MULTIPLY",e,e],[106,1,92,"NumpadSubtract",106,"NumPad_Subtract",109,"VK_SUBTRACT",e,e],[104,1,93,"NumpadAdd",104,"NumPad_Add",107,"VK_ADD",e,e],[3,1,94,"NumpadEnter",3,e,0,e,e,e],[94,1,95,"Numpad1",94,"NumPad1",97,"VK_NUMPAD1",e,e],[95,1,96,"Numpad2",95,"NumPad2",98,"VK_NUMPAD2",e,e],[96,1,97,"Numpad3",96,"NumPad3",99,"VK_NUMPAD3",e,e],[97,1,98,"Numpad4",97,"NumPad4",100,"VK_NUMPAD4",e,e],[98,1,99,"Numpad5",98,"NumPad5",101,"VK_NUMPAD5",e,e],[99,1,100,"Numpad6",99,"NumPad6",102,"VK_NUMPAD6",e,e],[100,1,101,"Numpad7",100,"NumPad7",103,"VK_NUMPAD7",e,e],[101,1,102,"Numpad8",101,"NumPad8",104,"VK_NUMPAD8",e,e],[102,1,103,"Numpad9",102,"NumPad9",105,"VK_NUMPAD9",e,e],[93,1,104,"Numpad0",93,"NumPad0",96,"VK_NUMPAD0",e,e],[107,1,105,"NumpadDecimal",107,"NumPad_Decimal",110,"VK_DECIMAL",e,e],[92,0,106,"IntlBackslash",92,"OEM_102",226,"VK_OEM_102",e,e],[58,1,107,"ContextMenu",58,"ContextMenu",93,e,e,e],[0,1,108,"Power",0,e,0,e,e,e],[0,1,109,"NumpadEqual",0,e,0,e,e,e],[71,1,110,"F13",71,"F13",124,"VK_F13",e,e],[72,1,111,"F14",72,"F14",125,"VK_F14",e,e],[73,1,112,"F15",73,"F15",126,"VK_F15",e,e],[74,1,113,"F16",74,"F16",127,"VK_F16",e,e],[75,1,114,"F17",75,"F17",128,"VK_F17",e,e],[76,1,115,"F18",76,"F18",129,"VK_F18",e,e],[77,1,116,"F19",77,"F19",130,"VK_F19",e,e],[0,1,117,"F20",0,e,0,"VK_F20",e,e],[0,1,118,"F21",0,e,0,"VK_F21",e,e],[0,1,119,"F22",0,e,0,"VK_F22",e,e],[0,1,120,"F23",0,e,0,"VK_F23",e,e],[0,1,121,"F24",0,e,0,"VK_F24",e,e],[0,1,122,"Open",0,e,0,e,e,e],[0,1,123,"Help",0,e,0,e,e,e],[0,1,124,"Select",0,e,0,e,e,e],[0,1,125,"Again",0,e,0,e,e,e],[0,1,126,"Undo",0,e,0,e,e,e],[0,1,127,"Cut",0,e,0,e,e,e],[0,1,128,"Copy",0,e,0,e,e,e],[0,1,129,"Paste",0,e,0,e,e,e],[0,1,130,"Find",0,e,0,e,e,e],[0,1,131,"AudioVolumeMute",112,"AudioVolumeMute",173,"VK_VOLUME_MUTE",e,e],[0,1,132,"AudioVolumeUp",113,"AudioVolumeUp",175,"VK_VOLUME_UP",e,e],[0,1,133,"AudioVolumeDown",114,"AudioVolumeDown",174,"VK_VOLUME_DOWN",e,e],[105,1,134,"NumpadComma",105,"NumPad_Separator",108,"VK_SEPARATOR",e,e],[110,0,135,"IntlRo",110,"ABNT_C1",193,"VK_ABNT_C1",e,e],[0,1,136,"KanaMode",0,e,0,e,e,e],[0,0,137,"IntlYen",0,e,0,e,e,e],[0,1,138,"Convert",0,e,0,e,e,e],[0,1,139,"NonConvert",0,e,0,e,e,e],[0,1,140,"Lang1",0,e,0,e,e,e],[0,1,141,"Lang2",0,e,0,e,e,e],[0,1,142,"Lang3",0,e,0,e,e,e],[0,1,143,"Lang4",0,e,0,e,e,e],[0,1,144,"Lang5",0,e,0,e,e,e],[0,1,145,"Abort",0,e,0,e,e,e],[0,1,146,"Props",0,e,0,e,e,e],[0,1,147,"NumpadParenLeft",0,e,0,e,e,e],[0,1,148,"NumpadParenRight",0,e,0,e,e,e],[0,1,149,"NumpadBackspace",0,e,0,e,e,e],[0,1,150,"NumpadMemoryStore",0,e,0,e,e,e],[0,1,151,"NumpadMemoryRecall",0,e,0,e,e,e],[0,1,152,"NumpadMemoryClear",0,e,0,e,e,e],[0,1,153,"NumpadMemoryAdd",0,e,0,e,e,e],[0,1,154,"NumpadMemorySubtract",0,e,0,e,e,e],[0,1,155,"NumpadClear",0,e,0,e,e,e],[0,1,156,"NumpadClearEntry",0,e,0,e,e,e],[5,1,0,e,5,"Ctrl",17,"VK_CONTROL",e,e],[4,1,0,e,4,"Shift",16,"VK_SHIFT",e,e],[6,1,0,e,6,"Alt",18,"VK_MENU",e,e],[57,1,0,e,57,"Meta",0,"VK_COMMAND",e,e],[5,1,157,"ControlLeft",5,e,0,"VK_LCONTROL",e,e],[4,1,158,"ShiftLeft",4,e,0,"VK_LSHIFT",e,e],[6,1,159,"AltLeft",6,e,0,"VK_LMENU",e,e],[57,1,160,"MetaLeft",57,e,0,"VK_LWIN",e,e],[5,1,161,"ControlRight",5,e,0,"VK_RCONTROL",e,e],[4,1,162,"ShiftRight",4,e,0,"VK_RSHIFT",e,e],[6,1,163,"AltRight",6,e,0,"VK_RMENU",e,e],[57,1,164,"MetaRight",57,e,0,"VK_RWIN",e,e],[0,1,165,"BrightnessUp",0,e,0,e,e,e],[0,1,166,"BrightnessDown",0,e,0,e,e,e],[0,1,167,"MediaPlay",0,e,0,e,e,e],[0,1,168,"MediaRecord",0,e,0,e,e,e],[0,1,169,"MediaFastForward",0,e,0,e,e,e],[0,1,170,"MediaRewind",0,e,0,e,e,e],[114,1,171,"MediaTrackNext",119,"MediaTrackNext",176,"VK_MEDIA_NEXT_TRACK",e,e],[115,1,172,"MediaTrackPrevious",120,"MediaTrackPrevious",177,"VK_MEDIA_PREV_TRACK",e,e],[116,1,173,"MediaStop",121,"MediaStop",178,"VK_MEDIA_STOP",e,e],[0,1,174,"Eject",0,e,0,e,e,e],[117,1,175,"MediaPlayPause",122,"MediaPlayPause",179,"VK_MEDIA_PLAY_PAUSE",e,e],[0,1,176,"MediaSelect",123,"LaunchMediaPlayer",181,"VK_MEDIA_LAUNCH_MEDIA_SELECT",e,e],[0,1,177,"LaunchMail",124,"LaunchMail",180,"VK_MEDIA_LAUNCH_MAIL",e,e],[0,1,178,"LaunchApp2",125,"LaunchApp2",183,"VK_MEDIA_LAUNCH_APP2",e,e],[0,1,179,"LaunchApp1",0,e,0,"VK_MEDIA_LAUNCH_APP1",e,e],[0,1,180,"SelectTask",0,e,0,e,e,e],[0,1,181,"LaunchScreenSaver",0,e,0,e,e,e],[0,1,182,"BrowserSearch",115,"BrowserSearch",170,"VK_BROWSER_SEARCH",e,e],[0,1,183,"BrowserHome",116,"BrowserHome",172,"VK_BROWSER_HOME",e,e],[112,1,184,"BrowserBack",117,"BrowserBack",166,"VK_BROWSER_BACK",e,e],[113,1,185,"BrowserForward",118,"BrowserForward",167,"VK_BROWSER_FORWARD",e,e],[0,1,186,"BrowserStop",0,e,0,"VK_BROWSER_STOP",e,e],[0,1,187,"BrowserRefresh",0,e,0,"VK_BROWSER_REFRESH",e,e],[0,1,188,"BrowserFavorites",0,e,0,"VK_BROWSER_FAVORITES",e,e],[0,1,189,"ZoomToggle",0,e,0,e,e,e],[0,1,190,"MailReply",0,e,0,e,e,e],[0,1,191,"MailForward",0,e,0,e,e,e],[0,1,192,"MailSend",0,e,0,e,e,e],[109,1,0,e,109,"KeyInComposition",229,e,e,e],[111,1,0,e,111,"ABNT_C2",194,"VK_ABNT_C2",e,e],[91,1,0,e,91,"OEM_8",223,"VK_OEM_8",e,e],[0,1,0,e,0,e,0,"VK_CLEAR",e,e],[0,1,0,e,0,e,0,"VK_KANA",e,e],[0,1,0,e,0,e,0,"VK_HANGUL",e,e],[0,1,0,e,0,e,0,"VK_JUNJA",e,e],[0,1,0,e,0,e,0,"VK_FINAL",e,e],[0,1,0,e,0,e,0,"VK_HANJA",e,e],[0,1,0,e,0,e,0,"VK_KANJI",e,e],[0,1,0,e,0,e,0,"VK_CONVERT",e,e],[0,1,0,e,0,e,0,"VK_NONCONVERT",e,e],[0,1,0,e,0,e,0,"VK_ACCEPT",e,e],[0,1,0,e,0,e,0,"VK_MODECHANGE",e,e],[0,1,0,e,0,e,0,"VK_SELECT",e,e],[0,1,0,e,0,e,0,"VK_PRINT",e,e],[0,1,0,e,0,e,0,"VK_EXECUTE",e,e],[0,1,0,e,0,e,0,"VK_SNAPSHOT",e,e],[0,1,0,e,0,e,0,"VK_HELP",e,e],[0,1,0,e,0,e,0,"VK_APPS",e,e],[0,1,0,e,0,e,0,"VK_PROCESSKEY",e,e],[0,1,0,e,0,e,0,"VK_PACKET",e,e],[0,1,0,e,0,e,0,"VK_DBE_SBCSCHAR",e,e],[0,1,0,e,0,e,0,"VK_DBE_DBCSCHAR",e,e],[0,1,0,e,0,e,0,"VK_ATTN",e,e],[0,1,0,e,0,e,0,"VK_CRSEL",e,e],[0,1,0,e,0,e,0,"VK_EXSEL",e,e],[0,1,0,e,0,e,0,"VK_EREOF",e,e],[0,1,0,e,0,e,0,"VK_PLAY",e,e],[0,1,0,e,0,e,0,"VK_ZOOM",e,e],[0,1,0,e,0,e,0,"VK_NONAME",e,e],[0,1,0,e,0,e,0,"VK_PA1",e,e],[0,1,0,e,0,e,0,"VK_OEM_CLEAR",e,e]];let K=[],t=[];for(const r of _){const[e,_,o,a,V,E,n,M,u,i]=r;if(t[o]||(t[o]=!0,scanCodeIntToStr[o]=a,scanCodeStrToInt[a]=o,scanCodeLowerCaseStrToInt[a.toLowerCase()]=o,_&&(IMMUTABLE_CODE_TO_KEY_CODE[o]=V,0!==V&&3!==V&&5!==V&&4!==V&&6!==V&&57!==V&&(IMMUTABLE_KEY_CODE_TO_CODE[V]=o))),!K[V]){if(K[V]=!0,!E)throw new Error(`String representation missing for key code ${V} around scan code ${a}`);uiMap.define(V,E),userSettingsUSMap.define(V,u||E),userSettingsGeneralMap.define(V,i||u||E)}n&&(EVENT_KEY_CODE_MAP[n]=V),M&&(NATIVE_WINDOWS_KEY_CODE_TO_KEY_CODE[M]=V)}IMMUTABLE_KEY_CODE_TO_CODE[3]=46})();export var KeyCodeUtils;(function(e){function _(e){return uiMap.keyCodeToStr(e)}function K(e){return uiMap.strToKeyCode(e)}function t(e){return userSettingsUSMap.keyCodeToStr(e)}function r(e){return userSettingsGeneralMap.keyCodeToStr(e)}function o(e){return userSettingsUSMap.strToKeyCode(e)||userSettingsGeneralMap.strToKeyCode(e)}function a(e){if(e>=93&&e<=108)return null;switch(e){case 16:return"Up";case 18:return"Down";case 15:return"Left";case 17:return"Right"}return uiMap.keyCodeToStr(e)}e.toString=_,e.fromString=K,e.toUserSettingsUS=t,e.toUserSettingsGeneral=r,e.fromUserSettings=o,e.toElectronAccelerator=a})(KeyCodeUtils||(KeyCodeUtils={}));export function KeyChord(e,_){const K=(65535&_)<<16>>>0;return(e|K)>>>0}