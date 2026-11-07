/* Automatically generated.  Do not edit */
/* See the tool/mkopcodeh.tcl script for details */
#define OP_Savepoint       0
#define OP_AutoCommit      1
#define OP_Transaction     2
#define OP_Checkpoint      3
#define OP_JournalMode     4
#define OP_Vacuum          5
#define OP_VFilter         6 /* jump, synopsis: iplan=r[P3] zplan='P4'     */
#define OP_VUpdate         7 /* synopsis: data=r[P3@P2]                    */
#define OP_Init            8 /* jump0, synopsis: Start at P2               */
#define OP_Goto            9 /* jump                                       */
#define OP_Gosub          10 /* jump                                       */
#define OP_InitCoroutine  11 /* jump0                                      */
#define OP_Yield          12 /* jump0                                      */
#define OP_MustBeInt      13 /* jump0                                      */
#define OP_Jump           14 /* jump                                       */
#define OP_Once           15 /* jump                                       */
#define OP_If             16 /* jump                                       */
#define OP_IfNot          17 /* jump                                       */
#define OP_IsType         18 /* jump, synopsis: if typeof(P1.P3) in P5 goto P2 */
#define OP_Not            19 /* same as TK_NOT, synopsis: r[P2]= !r[P1]    */
#define OP_IfNullRow      20 /* jump, synopsis: if P1.nullRow then r[P3]=NULL, goto P2 */
#define OP_SeekLT         21 /* jump0, synopsis: key=r[P3@P4]              */
#define OP_SeekLE         22 /* jump0, synopsis: key=r[P3@P4]              */
#define OP_SeekGE         23 /* jump0, synopsis: key=r[P3@P4]              */
#define OP_SeekGT         24 /* jump0, synopsis: key=r[P3@P4]              */
#define OP_IfNoHope       25 /* jump, synopsis: key=r[P3@P4]               */
#define OP_NoConflict     26 /* jump, synopsis: key=r[P3@P4]               */
#define OP_NotFound       27 /* jump, synopsis: key=r[P3@P4]               */
#define OP_Found          28 /* jump, synopsis: key=r[P3@P4]               */
#define OP_SeekRowid      29 /* jump0, synopsis: intkey=r[P3]              */
#define OP_NotExists      30 /* jump, synopsis: intkey=r[P3]               */
#define OP_Last           31 /* jump0                                      */
#define OP_IfSizeBetween  32 /* jump                                       */
#define OP_SorterSort     33 /* jump                                       */
#define OP_Sort           34 /* jump                                       */
#define OP_Rewind         35 /* jump0                                      */
#define OP_IfEmpty        36 /* jump, synopsis: if( empty(P1) ) goto P2    */
#define OP_SorterNext     37 /* jump                                       */
#define OP_Prev           38 /* jump                                       */
#define OP_Next           39 /* jump                                       */
#define OP_IdxLE          40 /* jump, synopsis: key=r[P3@P4]               */
#define OP_IdxGT          41 /* jump, synopsis: key=r[P3@P4]               */
#define OP_IdxLT          42 /* jump, synopsis: key=r[P3@P4]               */
#define OP_Or             43 /* same as TK_OR, synopsis: r[P3]=(r[P1] || r[P2]) */
#define OP_And            44 /* same as TK_AND, synopsis: r[P3]=(r[P1] && r[P2]) */
#define OP_IdxGE          45 /* jump, synopsis: key=r[P3@P4]               */
#define OP_IFindKey       46 /* jump                                       */
#define OP_RowSetRead     47 /* jump, synopsis: r[P3]=rowset(P1)           */
#define OP_RowSetTest     48 /* jump, synopsis: if r[P3] in rowset(P1) goto P2 */
#define OP_Program        49 /* jump0                                      */
#define OP_FkIfZero       50 /* jump, synopsis: if fkctr[P1]==0 goto P2    */
#define OP_IsNull         51 /* jump, same as TK_ISNULL, synopsis: if r[P1]==NULL goto P2 */
#define OP_NotNull        52 /* jump, same as TK_NOTNULL, synopsis: if r[P1]!=NULL goto P2 */
#define OP_Ne             53 /* jump, same as TK_NE, synopsis: IF r[P3]!=r[P1] */
#define OP_Eq             54 /* jump, same as TK_EQ, synopsis: IF r[P3]==r[P1] */
#define OP_Gt             55 /* jump, same as TK_GT, synopsis: IF r[P3]>r[P1] */
#define OP_Le             56 /* jump, same as TK_LE, synopsis: IF r[P3]<=r[P1] */
#define OP_Lt             57 /* jump, same as TK_LT, synopsis: IF r[P3]<r[P1] */
#define OP_Ge             58 /* jump, same as TK_GE, synopsis: IF r[P3]>=r[P1] */
#define OP_ElseEq         59 /* jump, same as TK_ESCAPE                    */
#define OP_IfPos          60 /* jump, synopsis: if r[P1]>0 then r[P1]-=P3, goto P2 */
#define OP_IfNotZero      61 /* jump, synopsis: if r[P1]!=0 then r[P1]--, goto P2 */
#define OP_DecrJumpZero   62 /* jump, synopsis: if (--r[P1])==0 goto P2    */
#define OP_IncrVacuum     63 /* jump                                       */
#define OP_VNext          64 /* jump                                       */
#define OP_Filter         65 /* jump, synopsis: if key(P3@P4) not in filter(P1) goto P2 */
#define OP_PureFunc       66 /* synopsis: r[P3]=func(r[P2@NP])             */
#define OP_Function       67 /* synopsis: r[P3]=func(r[P2@NP])             */
#define OP_Return         68
#define OP_EndCoroutine   69
#define OP_HaltIfNull     70 /* synopsis: if r[P3]=null halt               */
#define OP_Halt           71
#define OP_Integer        72 /* synopsis: r[P2]=P1                         */
#define OP_Int64          73 /* synopsis: r[P2]=PINT13                     */
#define OP_String         74 /* synopsis: r[P2]='P4' (len=P1)              */
#define OP_BeginSubrtn    75 /* synopsis: r[P2]=NULL                       */
#define OP_Null           76 /* synopsis: r[P2..P3]=NULL                   */
#define OP_SoftNull       77 /* synopsis: r[P1]=NULL                       */
#define OP_Blob           78 /* synopsis: r[P2]=P4 (len=P1)                */
#define OP_Variable       79 /* synopsis: r[P2]=parameter(P1)              */
#define OP_Move           80 /* synopsis: r[P2@P3]=r[P1@P3]                */
#define OP_Copy           81 /* synopsis: r[P2@P3+1]=r[P1@P3+1]            */
#define OP_SCopy          82 /* synopsis: r[P2]=r[P1]                      */
#define OP_IntCopy        83 /* synopsis: r[P2]=r[P1]                      */
#define OP_FkCheck        84
#define OP_ResultRow      85 /* synopsis: output=r[P1@P2]                  */
#define OP_CollSeq        86
#define OP_AddImm         87 /* synopsis: r[P1]=r[P1]+P2                   */
#define OP_RealAffinity   88
#define OP_Cast           89 /* synopsis: affinity(r[P1])                  */
#define OP_Permutation    90
#define OP_Compare        91 /* synopsis: r[P1@P3] <-> r[P2@P3]            */
#define OP_IsTrue         92 /* synopsis: r[P2] = coalesce(r[P1]==TRUE,P3) ^ P4 */
#define OP_ZeroOrNull     93 /* synopsis: r[P2] = 0 OR NULL                */
#define OP_Offset         94 /* synopsis: r[P3] = sqlite_offset(P1)        */
#define OP_Column         95 /* synopsis: r[P3]=PX cursor P1 column P2     */
#define OP_TypeCheck      96 /* synopsis: typecheck(r[P1@P2])              */
#define OP_Affinity       97 /* synopsis: affinity(r[P1@P2])               */
#define OP_MakeRecord     98 /* synopsis: r[P3]=mkrec(r[P1@P2])            */
#define OP_Count          99 /* synopsis: r[P2]=count()                    */
#define OP_ReadCookie    100
#define OP_SetCookie     101
#define OP_ReopenIdx     102 /* synopsis: root=P2 iDb=P3                   */
#define OP_BitAnd        103 /* same as TK_BITAND, synopsis: r[P3]=r[P1]&r[P2] */
#define OP_BitOr         104 /* same as TK_BITOR, synopsis: r[P3]=r[P1]|r[P2] */
#define OP_ShiftLeft     105 /* same as TK_LSHIFT, synopsis: r[P3]=r[P2]<<r[P1] */
#define OP_ShiftRight    106 /* same as TK_RSHIFT, synopsis: r[P3]=r[P2]>>r[P1] */
#define OP_Add           107 /* same as TK_PLUS, synopsis: r[P3]=r[P1]+r[P2] */
#define OP_Subtract      108 /* same as TK_MINUS, synopsis: r[P3]=r[P2]-r[P1] */
#define OP_Multiply      109 /* same as TK_STAR, synopsis: r[P3]=r[P1]*r[P2] */
#define OP_Divide        110 /* same as TK_SLASH, synopsis: r[P3]=r[P2]/r[P1] */
#define OP_Remainder     111 /* same as TK_REM, synopsis: r[P3]=r[P2]%r[P1] */
#define OP_Concat        112 /* same as TK_CONCAT, synopsis: r[P3]=r[P2]+r[P1] */
#define OP_OpenRead      113 /* synopsis: root=P2 iDb=P3                   */
#define OP_OpenWrite     114 /* synopsis: root=P2 iDb=P3                   */
#define OP_BitNot        115 /* same as TK_BITNOT, synopsis: r[P2]= ~r[P1] */
#define OP_OpenDup       116
#define OP_OpenAutoindex 117 /* synopsis: nColumn=P2                       */
#define OP_String8       118 /* same as TK_STRING, synopsis: r[P2]='P4'    */
#define OP_OpenEphemeral 119 /* synopsis: nColumn=P2                       */
#define OP_SorterOpen    120
#define OP_SequenceTest  121 /* synopsis: if( cursor[P1].ctr++ ) pc = P2   */
#define OP_OpenPseudo    122 /* synopsis: P3 columns in r[P2]              */
#define OP_Close         123
#define OP_ColumnsUsed   124 /* synopsis: Cursor P1 uses columns PHEX23    */
#define OP_SeekScan      125 /* synopsis: Scan-ahead up to P1 rows         */
#define OP_SeekHit       126 /* synopsis: set P2<=seekHit<=P3              */
#define OP_Sequence      127 /* synopsis: r[P2]=cursor[P1].ctr++           */
#define OP_NewRowid      128 /* synopsis: r[P2]=rowid                      */
#define OP_Insert        129 /* synopsis: intkey=r[P3] data=r[P2]          */
#define OP_RowCell       130
#define OP_Delete        131
#define OP_ResetCount    132
#define OP_SorterCompare 133 /* synopsis: if key(P1)!=trim(r[P3],P4) goto P2 */
#define OP_SorterData    134 /* synopsis: r[P2]=data                       */
#define OP_RowData       135 /* synopsis: r[P2]=data                       */
#define OP_Rowid         136 /* synopsis: r[P2]=PX rowid of P1             */
#define OP_NullRow       137
#define OP_SeekEnd       138
#define OP_IdxInsert     139 /* synopsis: key=r[P2]                        */
#define OP_SorterInsert  140 /* synopsis: key=r[P2]                        */
#define OP_IdxDelete     141 /* synopsis: key=r[P2@P5]                     */
#define OP_DeferredSeek  142 /* synopsis: Move P3 to P1.rowid if needed    */
#define OP_IdxRowid      143 /* synopsis: r[P2]=rowid                      */
#define OP_FinishSeek    144
#define OP_Destroy       145
#define OP_Clear         146
#define OP_ResetSorter   147
#define OP_CreateBtree   148 /* synopsis: r[P2]=root iDb=P1 flags=P3       */
#define OP_SqlExec       149
#define OP_ParseSchema   150
#define OP_LoadAnalysis  151
#define OP_DropTable     152
#define OP_DropIndex     153
#define OP_Real          154 /* same as TK_FLOAT, synopsis: r[P2]=PDBL13   */
#define OP_DropTrigger   155
#define OP_IntegrityCk   156
#define OP_RowSetAdd     157 /* synopsis: rowset(P1)=r[P2]                 */
#define OP_Param         158
#define OP_FkCounter     159 /* synopsis: fkctr[P1]+=P2                    */
#define OP_MemMax        160 /* synopsis: r[P1]=max(r[P1],r[P2])           */
#define OP_OffsetLimit   161 /* synopsis: if r[P1]>0 then r[P2]=r[P1]+max(0,r[P3]) else r[P2]=(-1) */
#define OP_AggInverse    162 /* synopsis: accum=r[P3] inverse(r[P2@P5])    */
#define OP_AggStep       163 /* synopsis: accum=r[P3] step(r[P2@P5])       */
#define OP_AggStep1      164 /* synopsis: accum=r[P3] step(r[P2@P5])       */
#define OP_AggValue      165 /* synopsis: r[P3]=value N=P2                 */
#define OP_AggFinal      166 /* synopsis: accum=r[P1] N=P2                 */
#define OP_Expire        167
#define OP_CursorLock    168
#define OP_CursorUnlock  169
#define OP_TableLock     170 /* synopsis: iDb=P1 root=P2 write=P3          */
#define OP_VBegin        171
#define OP_VCreate       172
#define OP_VDestroy      173
#define OP_VOpen         174
#define OP_VCheck        175
#define OP_VInitIn       176 /* synopsis: r[P2]=ValueList(P1,P3)           */
#define OP_VColumn       177 /* synopsis: r[P3]=vcolumn(P2)                */
#define OP_VRename       178
#define OP_Pagecount     179
#define OP_MaxPgcnt      180
#define OP_ClrSubtype    181 /* synopsis: r[P1].subtype = 0                */
#define OP_GetSubtype    182 /* synopsis: r[P2] = r[P1].subtype            */
#define OP_SetSubtype    183 /* synopsis: r[P2].subtype = r[P1]            */
#define OP_FilterAdd     184 /* synopsis: filter(P1) += key(P3@P4)         */
#define OP_Trace         185
#define OP_CursorHint    186
#define OP_ReleaseReg    187 /* synopsis: release r[P1@P2] mask P3         */
#define OP_Noop          188
#define OP_Explain       189
#define OP_Abortable     190

/* Properties such as "out2" or "jump" that are specified in
** comments following the "case" for each opcode in the vdbe.c
** are encoded into bitvectors as follows:
*/
#define OPFLG_JUMP        0x01  /* jump:  P2 holds jmp target */
#define OPFLG_IN1         0x02  /* in1:   P1 is an input */
#define OPFLG_IN2         0x04  /* in2:   P2 is an input */
#define OPFLG_IN3         0x08  /* in3:   P3 is an input */
#define OPFLG_OUT2        0x10  /* out2:  P2 is an output */
#define OPFLG_OUT3        0x20  /* out3:  P3 is an output */
#define OPFLG_NCYCLE      0x40  /* ncycle:Cycles count against P1 */
#define OPFLG_JUMP0       0x80  /* jump0:  P2 might be zero */
#define OPFLG_INITIALIZER {\
/*   0 */ 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x41, 0x00,\
/*   8 */ 0x81, 0x01, 0x01, 0x81, 0x83, 0x83, 0x01, 0x01,\
/*  16 */ 0x03, 0x03, 0x01, 0x12, 0x01, 0xc9, 0xc9, 0xc9,\
/*  24 */ 0xc9, 0x49, 0x49, 0x49, 0x49, 0xc9, 0x49, 0xc1,\
/*  32 */ 0x01, 0x41, 0x41, 0xc1, 0x01, 0x01, 0x41, 0x41,\
/*  40 */ 0x41, 0x41, 0x41, 0x26, 0x26, 0x41, 0x09, 0x23,\
/*  48 */ 0x0b, 0x81, 0x01, 0x03, 0x03, 0x0b, 0x0b, 0x0b,\
/*  56 */ 0x0b, 0x0b, 0x0b, 0x01, 0x03, 0x03, 0x03, 0x01,\
/*  64 */ 0x41, 0x01, 0x00, 0x00, 0x02, 0x02, 0x08, 0x00,\
/*  72 */ 0x10, 0x10, 0x10, 0x00, 0x10, 0x00, 0x10, 0x10,\
/*  80 */ 0x00, 0x00, 0x10, 0x10, 0x00, 0x00, 0x00, 0x02,\
/*  88 */ 0x02, 0x02, 0x00, 0x00, 0x12, 0x1e, 0x20, 0x40,\
/*  96 */ 0x00, 0x00, 0x00, 0x10, 0x10, 0x00, 0x40, 0x26,\
/* 104 */ 0x26, 0x26, 0x26, 0x26, 0x26, 0x26, 0x26, 0x26,\
/* 112 */ 0x26, 0x40, 0x00, 0x12, 0x40, 0x40, 0x10, 0x40,\
/* 120 */ 0x00, 0x00, 0x00, 0x40, 0x00, 0x40, 0x40, 0x10,\
/* 128 */ 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00,\
/* 136 */ 0x50, 0x00, 0x40, 0x04, 0x04, 0x00, 0x40, 0x50,\
/* 144 */ 0x40, 0x10, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00,\
/* 152 */ 0x00, 0x00, 0x10, 0x00, 0x00, 0x06, 0x10, 0x00,\
/* 160 */ 0x04, 0x1a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,\
/* 168 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x10,\
/* 176 */ 0x50, 0x40, 0x00, 0x10, 0x10, 0x02, 0x12, 0x12,\
/* 184 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,}

/* The resolve3P2Values() routine is able to run faster if it knows
** the value of the largest JUMP opcode.  The smaller the maximum
** JUMP opcode the better, so the mkopcodeh.tcl script that
** generated this include file strives to group all JUMP opcodes
** together near the beginning of the list.
*/
#define SQLITE_MX_JUMP_OPCODE  65  /* Maximum JUMP opcode */
