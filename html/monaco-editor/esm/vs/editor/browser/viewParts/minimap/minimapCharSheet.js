export const allCharCodes=(()=>{const t=[];for(let e=32;e<=126;e++)t.push(e);return t.push(65533),t})();export const getCharIndex=(t,e)=>(t-=32,t<0||t>96?e<=2?(t+96)%96:95:t);