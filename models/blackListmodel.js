const mongoose=require('mongoose');

const blackSchema=new mongoose.Schema({
token:String    
})

const blacklistModel=mongoose.model('Blacklist',blackSchema);

module.exports={blacklistModel};