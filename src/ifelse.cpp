#include <libsnark/common/default_types/r1cs_gg_ppzksnark_pp.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp>
#include <libsnark/gadgetlib1/pb_variable.hpp>
#include <libsnark/gadgetlib1/gadgets/basic_gadgets.hpp>

using namespace libsnark;
using namespace std;

/*
def f(x, y, z):
  if x == 1:
    return y*z
  return 2y - z

Polynomial Constraints:
(x-1)*b=0
(x-t)*(1-b)=0
b*y*z+(1-b)*(2y - z)=out
(t-t1)*(t-t2)=0

Range Constraints:
t1<1
t2>1

R1CS for Polynomial Constraints:
x*b=b
(x-t)*(1-b) = 0
b*y=sym1
sym1*z=sym2
(1-b)*(2y - z) = sym3
sym2 + sym3 = out
*/

int main () {
    typedef libff::Fr<default_r1cs_gg_ppzksnark_pp> FieldT;

    // Initialize the curve parameters
    default_r1cs_gg_ppzksnark_pp::init_public_params();
  
    // Create protoboard
    protoboard<FieldT> pb;

    // Define variables
    pb_variable<FieldT> x, y, z;
    pb_variable<FieldT> sym1, sym2, sym3;
    // pb_variable<FieldT> z;
    pb_variable<FieldT> b, t, t1, t2;
    pb_variable<FieldT> out;
    pb_variable<FieldT> t1max, t2min;
    pb_variable<FieldT> t1less, t1less_or_eq;
    pb_variable<FieldT> t2less, t2less_or_eq;

    // Allocate variables to protoboard
    // The strings (like "x") are only for debugging purposes   
    out.allocate(pb, "out");
    x.allocate(pb, "x");
    y.allocate(pb, "y");
    z.allocate(pb, "z");
    b.allocate(pb, "b");
    t.allocate(pb, "t"); 
    t1.allocate(pb, "t1");
    t2.allocate(pb, "t2");
    t1max.allocate(pb, "t1max");
    t2min.allocate(pb, "t2min");
    // sym1.allocate(pb, "sym1");
    sym1.allocate(pb, "sym1");
    sym2.allocate(pb, "sym2");
    sym3.allocate(pb, "sym3");

    // This sets up the protoboard variables
    // so that the first one (out) represents the public
    // input and the rest is private input
    pb.set_input_sizes(1);

    // Add R1CS constraints to protoboard

    // add comparision constrains

    // x.allocate(pb, "x");
    // max.allocate(pb, "max");
    
    pb.val(t1max)= 1;
    pb.val(t2min)= 1;

    comparison_gadget<FieldT> cmp1(pb, 10, t1, t1max, t1less, t1less_or_eq, "cmp");
    comparison_gadget<FieldT> cmp2(pb, 20, t2min, t2, t2less, t2less_or_eq, "cmp");
    cmp1.generate_r1cs_constraints();
    cmp2.generate_r1cs_constraints();
    pb.add_r1cs_constraint(r1cs_constraint<FieldT>(t1less, 1, FieldT::one()));
    pb.add_r1cs_constraint(r1cs_constraint<FieldT>(t2less, 1, FieldT::one()));


    // add polynomial constrains
    // x*b=b
    pb.add_r1cs_constraint(r1cs_constraint<FieldT>(x, b, b));

    // (x-t)*(1-b) = 0
    pb.add_r1cs_constraint(r1cs_constraint<FieldT>(x-t, 1-b, 0));

    // b*y=sym1
    pb.add_r1cs_constraint(r1cs_constraint<FieldT>(b, y, sym1));

    // sym1*z=sym2
    pb.add_r1cs_constraint(r1cs_constraint<FieldT>(sym1, z, sym2));

    // // (1-b)*(2y - z) = sym3
    pb.add_r1cs_constraint(r1cs_constraint<FieldT>(1-b, 2*y-z, sym3));

    // // sym2 = out - sym3
    pb.add_r1cs_constraint(r1cs_constraint<FieldT>(sym2, 1, out-sym3));
    
    const r1cs_constraint_system<FieldT> constraint_system = pb.get_constraint_system();

    // generate keypair
    const r1cs_gg_ppzksnark_keypair<default_r1cs_gg_ppzksnark_pp> keypair = r1cs_gg_ppzksnark_generator<default_r1cs_gg_ppzksnark_pp>(constraint_system);

    // Add public input and witness values

    // given x,y,z, calculate correct secret inputs
    int vx = 1;
    int vy = 33;
    int vz = 55;
    int vout, vb, vt, vt1, vt2, vsym1, vsym2, vsym3;
    if(vx == 1){
        vout=vy * vz;
        vb=1;
        int rdm = 4;
        vt1  = 2-rdm;
        vt2 = rdm;
    }else{
        if (vx > 1){
            vt1  = 2-vx;
            vt2 = vx;
        }else{
            vt1  = vx;
            vt2 = 2-vx;
        }
        vout=2 * vy - vz;
        vb=0;
    }
    vt = vx;
    vsym1 = vb*vy;
    vsym2 = vsym1*vz;
    vsym3 = (1-vb) * (2*vy-vz);
    
    pb.val(out) = vout;
    pb.val(x) = vx;
    pb.val(t) = vt;
    pb.val(t1) = vt1;
    pb.val(t2) = vt2;
    pb.val(b) = vb;
    pb.val(sym1) = vsym1;
    pb.val(sym2) = vsym2;
    pb.val(sym3) = vsym3;
    pb.val(y) = vy;
    pb.val(z) = vz;

    cmp1.generate_r1cs_witness();
    cmp2.generate_r1cs_witness();

    // generate proof
    const r1cs_gg_ppzksnark_proof<default_r1cs_gg_ppzksnark_pp> proof = r1cs_gg_ppzksnark_prover<default_r1cs_gg_ppzksnark_pp>(keypair.pk, pb.primary_input(), pb.auxiliary_input());

    cout << "Secret Inputs: x=" << vx << ", y=" << vy << ", z=" << vz << ", f(x,y,z)=" << vout << endl;
    cout << "The Proof: " << proof << endl;
    // verify
    bool verified = r1cs_gg_ppzksnark_verifier_strong_IC<default_r1cs_gg_ppzksnark_pp>(keypair.vk, pb.primary_input(), proof);

    cout << "Number of R1CS constraints: " << constraint_system.num_constraints() << endl;
    // cout << "Primary (public) input: " << pb.primary_input() << endl;
    // cout << "Auxiliary (private) input: " << pb.auxiliary_input() << endl;
    cout << "Verification status: " << verified << endl;

    return 0;
}
