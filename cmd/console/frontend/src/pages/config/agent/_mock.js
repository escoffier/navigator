export default {
  'POST /api/v1/config/agents': (req, res) => {
    console.log(req.body)
    if (req.body) {
      return res.status(200).json({message: "创建成功"})
    } else {
      return res.status(500).json({error: "Failed"})
    }
  },
};
