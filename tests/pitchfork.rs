extern crate llvm_ir;
extern crate pitchfork;

use pitchfork::{
    AbstractData,
    AbstractValue,
    Config,
    PitchforkConfig,
    Project,
    StructDescriptions,
    check_for_ct_violation,
};

fn run_pitchfork(fn_name: &String,
                 args: &Option<Vec<AbstractData>>,
                 struct_desc: &StructDescriptions) {
    // Path to generated bitcode
    let mut bc_path = std::env::current_exe().unwrap();
    bc_path.pop();

    let project = Project::from_bc_dir(&bc_path, "bc").unwrap();

    // Get all mangled function names for ConstantTimeEq implementations
    let ct_func_names = project
        .all_functions()
        .filter(|x| x.0.name.contains(fn_name))
        .collect::<Vec<(&llvm_ir::Function, &llvm_ir::module::Module)>>();

    let mut config = Config::default();
    config.loop_bound = 100;

    // Test each function for constant-time violations
    for func in ct_func_names {
        let result = check_for_ct_violation(&func.0.name,
                                            &project,
                                            args.clone(),
                                            &struct_desc,
                                            config.clone(),
                                            &PitchforkConfig::default());

        if result.path_results.len() != 0 {
            panic!("Constant-time result:\n\n{}", &result);
        }
    }
}

#[test]
fn test_ct_abs64() {
    let args = Some(vec![
         AbstractData::pub_pointer_to(AbstractData::sec_integer(64)),
         AbstractData::sec_i64(),
    ]);

    let sd = StructDescriptions::new();

    run_pitchfork(&String::from("secp256k1_sign_and_abs64"), &args, &sd);
}

#[test]
fn test_ct_sign() {
    let args = Some(vec![
         AbstractData::pub_pointer_to(AbstractData::default()),
         AbstractData::pub_pointer_to(AbstractData::default()),
         AbstractData::pub_pointer_to(AbstractData::default()),
         AbstractData::pub_pointer_to(AbstractData::secret()),
         AbstractData::pub_pointer_to(AbstractData::default()),
         AbstractData::pub_pointer_to(AbstractData::default()),
         AbstractData::pub_pointer_to(AbstractData::pub_i8(AbstractValue::Unconstrained)),
    ]);

    let sd = StructDescriptions::new();

    run_pitchfork(&String::from("secp256k1_ecdsa_sign"), &args, &sd);
}

#[test]
fn test_ct_ecdh() {
    let args = Some(vec![
         AbstractData::pub_pointer_to(AbstractData::default()),
         AbstractData::pub_pointer_to(AbstractData::default()),
         AbstractData::pub_pointer_to(AbstractData::default()),
         AbstractData::pub_pointer_to(AbstractData::secret()),
         AbstractData::default(),
         AbstractData::pub_pointer_to(AbstractData::default()),
    ]);

    let sd = StructDescriptions::new();

    run_pitchfork(&String::from("secp256k1_ecdh"), &args, &sd);
}
