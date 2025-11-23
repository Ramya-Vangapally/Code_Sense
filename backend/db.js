const mongoose=require("mongoose");
const dotenv=require("dotenv");
dotenv.config();
const connectDB=async()=>{
    try{
         await mongoose.connect(process.env.MONGO_URI,{
                dbName: "codesense"
         });
         
         console.log("Mongodb connected");
    }
    catch(err){
        console.log("Mongodb failed to connect");
    }
}
module.exports=connectDB;
