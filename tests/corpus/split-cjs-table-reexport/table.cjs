console.log("table: init");
const receiverKind = () => typeof this;
let reads = 0;
module.exports = {
  n: 9,
  render: function (name) {
    return "table " + name;
  },
  get label() {
    return "literal";
  },
  get value() {
    return ++reads;
  },
  get pair() {
    reads++;
    return { left: reads, right: reads };
  },
  get 0() {
    return ++reads;
  },
  receiverKind,
};
