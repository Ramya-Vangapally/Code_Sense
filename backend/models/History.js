const mongoose=require("mongoose")
const HistorySchema=new mongoose.Schema({
    username:{type:String,required:true,unique:true},
    role:{type:String,required:true},
    Action:{type:String,required:true},
    language:{type:String,required:true},
    time:{type:Date,default:Date.now()}
});
module.exports=mongoose.model("User_history",HistorySchema,"history")