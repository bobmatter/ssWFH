// async function hi(){
//     console.log("hi");
//     await setTimeout(()=>{
//          console.log("message seen slow internet");
//     },3000)
//     console.log("hi returned");
// }
// hi()
// console.log("you have a bad attitude bye");
function delay(ms) {
    return new Promise(resolve => {
        setTimeout(resolve, ms);
    });
}

async function hi() {
    console.log("hi");

    await delay(3000);

    console.log("message seen slow internet");
    console.log("hi returned");
}

hi();
console.log("you have a bad attitude bye");
