---
title: "Machine Learning"
subtitle: "有一种什么都学了但什么都没学的感觉"
layout: post
author: "Zhuhai"
header-style: text
tags:
  - Lab0 Machine Learning 学习总结
---


## chap2 机器学习基本概念

### 名词
`数据集 Data Set` : 一组标记好 `特征 Feature` 和 `标签 Label` 的 `样本 Sample` ，包含 `训练集 Training Set/Sample` 和 `测试集 Test Set/Sample` 。

其中，特征由 D 维`特征向量` $x=[x_1,x_2,...,x_D]^T$ 表示，标签由标量 $y$ 表示。

则独立同分布的 N 个样本组成的训练集 D 可以记为 $D = [(x^{(1)},y^{(1)},(x^{(2)},y^{(2)}),...,(x^{(N)},y^{(N)}))]$

预测函数： $f^*(x)$ ，从一个函数集合中自动寻找最优函数近似每个样本的特征向量和标签之间的真实映射关系。

评价方法： $Acc(f^*(x))$

![](https://raw.githubusercontent.com/Zhuhai0247/blog-img/master/202210102125946.png)

### 机器学习三要素：模型，学习准则，优化算法

#### 模型：线性与非线性模型

- 概念：由输入产生正确输出的函数 / 概率模型。求出该模型是最终目标。
- 作用：确定 `假设空间`（输入空间到输出空间的映射的集合）

#### 学习准则（策略）：选择模型
- 概念：从集合中选择具体的模型，即策略。策略方法分为有损失函数与风险函数两种。
  - 损失函数：定义在单个样本，度量预测错误的程度。
    - `0-1损失函数`： $ℒ(𝑦,f(x;\theta))=I(y\neq f(x;\theta))$
    - `平方损失函数`：$ℒ(𝑦,f(x;\theta))=\frac{1}{2}(y-f(x;\theta))$
    - `交叉熵损失函数`：度量概率分布间的差异性。$ℒ(𝑦,f(x;\theta))=-\sum^C_{c=1}y_clnf_c(x;\theta)$
      - 信息熵：$H(X)=-\sum^n_{i=1}P(x_i)ln(P(x_i))$
      - 相对熵（KL散度）：$D_{KL}(p||q)=\sum^n_{i=1}p(x_i)ln(\frac{p(x_i)}{q(x_i)})$，其中P(x)为样本真实分布，Q(x)为模型所预测的分布。
      - 交叉熵：相对熵 + 信息熵，根据对数加减原理(提一个负号出来)，交叉熵 $H(p,q)=-\sum^n_{i=1}p(x_i)ln(q(x_i))$
    - `Hinge损失函数`：$ℒ(𝑦,f(x;\theta))=max(0,1-yf(x;\theta))$
  - 风险（代价）函数：定义在整个训练集上。
    - 经验风险：每个样本的平均损失。$R^{emp}_D(\theta)=\frac{1}{N}\sum^N_{n=1}ℒ(y^{(n)},f(x^{(n)};\theta))$
    - 结构风险：防止模型过拟合加入正则化项。

#### 优化算法：求解模型参数

- 概念：机器学习的训练过程其实就是最优化问题的求解过程。
  - 超参数：定义模型结构或优化策略，无需学习，凭靠经验。
  - 参数：即𝑓(𝒙; 𝜃)中的 𝜃，通过优化算法进行学习。 
- 梯度下降法：通过迭代找到目标函数的最小值，或者收敛到最小值。
  - 梯度：多变量微分的一般化，分别对每个变量微分后组成的向量集合。梯度的方向为函数在给定点上升最快的方向。故沿梯度反向即下降最快。
  - 批量梯度下降法(BGD)：目标函数为整个训练集上的风险函数：$\theta _{t+1}=\theta _t - \alpha \frac{\partial{R_D(\theta)}}{\partial{\theta}}$，其中 $\alpha$ 为`学习率`。
  - 提前停止：每次迭代后，新模型在测试集测试，若错误率不再下降，则停止。
  - 随机梯度下降法（SGD）：为减少迭代的计算复杂度，每次迭代时只（随机）采集一个样本，计算这个样本损失函数的梯度并更新参数。
  - 小批量梯度下降法：充分利用计算机的并行计算能力，每次随机抽取K个样本计算风险函数再进行迭代。


## chap3 线性模型

概念：通过样本特征的线性组合来进行预测的模型。
模型形式（判别函数）：$f(x;w)=w^Tx+b$，w 为权重向量， b 为偏置。
决策函数：将模型值域放缩到可预测的范围
$g(·)  ---> y=g(f(x;w))$


#### 线性判别函数和决策边界

分类：二分类（只需要一个线性判别函数，满足函数为0的点组成一个分割超平面，即决策平面）；多分类（一对其余；一对一；argmax）

#### Logistic回归：二分类

激活函数：Logistic函数 $y=g(·)=\frac{1}{1+exp(-w^Tx)}$，这里的w,x已增广。

标签：$y=\{0,1\}$，则$q(y=1 | x) = \frac{1}{1+exp(-w^Tx)}，q(y=0 | x)=1-q(y=1|x)$。

损失函数：采用交叉熵作为损失函数。

风险函数：$R(w)=-\frac{1}{N}\sum^N_{n=1}(p(y^{(n)}=1|x^{(n)})ln(g(w^Tx^{(n)}))+p(y^{(n)}=0|x^{(n)})ln(1-g(w^Tx^{(n)})))$。

梯度下降：$w_{t+1}<--w_t+\alpha \frac{1}{N}\sum^N_{n=1}x^{(n)}(p(y=1|x^{(n)})-g(w^Tx^{(n)})_{w_t})$，其中p为其真实概率，g(wx)为预测概率。

#### softmax回归：多分类

激活函数：Softmax函数$z_k=softmax(x_k)=\frac{exp(x_k)}{\sum_{i=1}^Kexp(x_i)}$

标签：$y=\{1,2,...,C\}$，则$q(y=c|x)=softmax(w^T_cx)$

决策函数：$y=argmax^C_{c=1}q(y=c|x)$

损失函数：采用交叉熵作为损失函数。

风险函数：$R(w)=-\frac{1}{N}\sum^N_{n=1}(p(y=c|x)ln(argmax^C_{c=1}q(y=c|x)))$，其中p为真实概率，q为预测概率。

梯度下降：$w_{t+1}<--w_t+\alpha \frac{1}{N}\sum^N_{n=1}x^{(n)}(p(y=c|x^{(n)})-q(y=c|x^{(n)})_{w_t})$

#### 支持向量机SVM：二分类



## 前馈神经网络

#### Sigmoid型函数

一类 S 型曲线函数，两端饱和：
- Logistic函数：$\sigma (x) = \frac{1}{1+exp(-x)}$，将实数域挤压到[0,1]
  - 近似函数：max(min(0.25x+0.5,1),0)
- Tanh函数：$tanh(x)=\frac{exp(x)-exp(-x)}{exp(x)+exp(-x)}$，将实数域挤压到[-1,1]
  - 近似函数：max(min(x,1),-1)

#### ReLU函数

- ReLU 是一个斜坡函数：$ReLU(x)=max(0,x)$
- 带泄露的 ReLU 函数避免死亡ReLU函数，在输入小于0时保留一个梯度防止神经元不能被激活：$LeakyReLU(x)=max(0,x)+y*min(0,x)=max(x,yx)$，一般y很小，如0.01。
-  带参数的 ReLU 引入一个可学习的参数，对于第 i 个神经元：$PReLU_i(x)=max(0,x)+y_imin(0,x)$
-  ELU 是一个近似的零中心化的非线性函数：$ELU(x)=max(0,x)+min(0,y(exp(x)-1))$，其中 y 是一个超参数。
-  Softplus 是 ReLU 函数的平滑版本：$Softplus(x)=ln(1+exp(x))$

#### 前馈网络

可看为一个有向无环图，包括全连接前馈网络和卷积神经网络。

#### 全连接前馈神经网络

- 第0层称为`输入层`，最后一层称为`输出层`，其他中间层称为`隐藏层`。
  - $input_i = Weight_i*output_{i-1}+bias_i$
  - $output_i=activationf_i(input_i)$
  - $x=input_0->output_1->input_1->output_2->...->z_i->a_i->...->output$
- 将多层前馈神经网络看作特征转换方法，使其最终输出作为分类器的输入进行分类。
  - 二分类问题：采用 Logistic 回归，即输出层为一个神经元，且激活函数为 Logistic 函数。
  - 多分类问题：采用 Softmax 回归，相当于输出层设置 C 个神经元，其激活函数为 Softmax 函数。

- 参数学习
  - 损失函数（采用交叉熵损失函数）：$ℒ(y,y')=-y^Tlny'$，其中样本为(x,y)，y为真实值，y'为预测值。
  - 风险函数（结构化风险函数）：$R(W,b)=\frac{1}{N}\sum^N_{n=1}ℒ(y^{(n)},y'^{(n)})+\frac{1}{2}\lambda||W||^2_F$
    - 这里 $|W||^2_F$ 为 Frobenius 范数：$|W||^2_F = \sum^L_{l=1}\sum^{M_l}_{i=1}\sum^{M_{l-1}}_{j=1}(w_{ij}^{(l)})^2$
  - 梯度下降法：需要计算W,b两个梯度。

- 反向传播算法
  > [参考](https://blog.csdn.net/ft_sunshine/article/details/90221691),利用链式法则计算误差项。
  - 为避免计算复杂梯度所设计。

- 自动梯度计算：
  - 数值微分：难点在于如何找到扰动x。
  - 符号微分。
  - 自动微分。

- 参数学习
  - 非凸优化问题
  - 梯度消失问题


## chap5 卷积神经网络

### 网络结构和相关概念

- 目前卷积神经网络一般是由卷积层、汇聚层和全连接层交叉堆叠而成的前馈神经网络。
  - 特点：局部连接；权重共享；汇聚。
  - 优点：不变性；参数少。


> [卷积、池化相关概念参考](https://blog.csdn.net/quiet_girl/article/details/84579038)
- 卷积：输入和卷积核的内积运算。
  - 卷积的三种模型
    - Full模式：第一个窗口只包含1个输入的元素，即从卷积核（fileter）和输入刚相交开始做卷积。没有元素的部分做补0操作。
    - Valid模式：卷积核和输入完全相交开始做卷积，这种模式不需要补0。
    - Same模式：当卷积核的中心C和输入开始相交时做卷积。没有元素的部分做补0操作。
  - 卷积核一般为奇数，此时有中心像素点，方便定位卷积核。
  - 反卷积：将输出(feature map)还原，这里的还原指维度上的相等。
- 池化(汇聚)：起到降维的作用。
  - 最大池化：对局部的值取最大值。
  - 平均池化：对局部的值取平均。
  - 随机池化：根据概率对局部值采样。
  - 反池化
    - 反最大池化：其他位置添零，需记录最大值原位置。
    - 反平均池化：全填均值即可，无需记录原位置。

### 卷积层

一般来说，一个卷积层的操作包括：
1. 用卷积核 $W^{p,1},W^{p,2},...,W^{p,D}$ 分别对输入特征映射 $X^1,X^2,...,X^D$ 进行卷积。
2. 将卷积结果相加，并加上偏置 $bias^p$，得到卷积层的净输入 $Z^p$ 。
3. 经过非线性激活函数(ReLU)后，最终得到输出特征映射 $Y^p$。

- 整体结构：输入 -> 【[卷积 -> ReLU] \* (2,5) -> 汇聚层 * (0,1)】\* (1,100) -> 全连接层 * (0,2)
- 参数学习：整体来说，卷积网络中参数为卷积核的权重以及偏置。类似于全连接前馈网络，卷积网络也可以通过误差反向传播算法进行参数学习。




### 代码阅读及函数积累

**Conv2D**：卷积
```py
from tensorflow.keras.layers import Conv2D

# 参数

Conv2D( inputs,         # 把上一层的输出作为输入
        input_shape,    # 输入形状
        filters,        # 卷积过滤器的数量,对应输出的维数
        padding,        # valid;same;full
        activation,     # 激活函数,None是线性函数
        ...
        )
```

**MaxPooling2D** / **tf.nn.max_pool**：池化(最大值策略)

```py
from tensorflow.keras.layers import MaxPooling2D

# 参数

MaxPooling2D( pool_size=(x,y),  # 配置池化窗口的维度，包括长和宽。
                                # 数值是包含两个整型元素值的列表或者元组。
              strides=x,        # 步长
              padding,          # 同上
              data_format       # 配置输入图像数据的格式，默认格式是channels_last，
                                # 也可以是根据需要设置成channels_first。
                                # 在进行图像数据处理时，图像数据的格式分为
                                # channels_last(batch, height, width, channels)和
                                # channels_first(batch, channels, height, width)。

)

pooling = tf.nn.max_pool(   
                    h,   
                    ksize=[1, height, width, 1],  
                    strides=[1, 1, 1, 1],  
                    padding='valid',
                    name="pool")

'''
h : 需要池化的输入，一般池化层接在卷积层后面，
输入通常是feature map，依然是[batch_size, height, width, channels]这样的shape
k_size : 池化窗口的大小，取一个四维向量，
一般是[1, height, width, 1]，因为一般不想在batch和channels上做池化，
所以这两个维度设为了1
strides : 窗口在每一个维度上滑动的步长，一般也是[1, stride,stride, 1]
'''

```

**Flatten**：用于将输入层的数据压成一维的数据，一般用于卷积层和全连接层之间（因为全连接层只能接收一维数据，而卷积层可以处理二维数据，就是全连接层处理的是向量，而卷积层处理的是矩阵），不改变batch，将其他维压缩成一维。

```py

from tensorflow.keras.layers import Flatten
#Example:

model = Sequential()
model.add(Convolution2D(64, 3, 3,
                        border_mode='same',
                        input_shape=(3, 32, 32)))
# now: model.output_shape == (None, 64, 32, 32)

model.add(Flatten())
# now: model.output_shape == (None, 65536)
```

**Dense**：f.keras.layers.Dense相当于在全连接层中添加一个层。Dense实现操作 output = activation（dot（input，kernel）+ bias） 其中，activation是用activation参数传递的逐元素激活函数，kernel是该层创建的权重矩阵，bias是由图层创建的偏差向量（仅在use_bias为True时适用）。

```py
tf.keras.layers.Dense(
    units,                                 # 正整数，输出空间的维数
    activation=None,                       # 激活函数，不指定则没有
    use_bias=True,		           # 布尔值，是否使用偏移向量
    kernel_initializer='glorot_uniform',   # 核权重矩阵的初始值设定项
    bias_initializer='zeros',              # 偏差向量的初始值设定项
    kernel_regularizer=None,               # 正则化函数应用于核权矩阵
    bias_regularizer=None,                 # 应用于偏差向量的正则化函数
    ...
)

# 实例
import tensorflow as tf

x = tf.random.normal([4, 784])

net = tf.keras.layers.Dense(512)
out = net(x)

out.shape
# TensorShape([4, 512])

net.kernel.shape, net.bias.shape
# (TensorShape([784, 512]), TensorShape([512]))

```

**optimizers.Adam()**：该函数解决监督学习使用梯度下降法时的学习率控制问题。大概的思想是开始的学习率设置为一个较大的值，然后根据次数的增多，动态的减小学习率，以实现效率和效果的兼得。

```py
from tensorflow.keras import optimizers

keras.optimizers.Adam(lr=0.001, beta_1=0.9, beta_2=0.99, epsilon=1e-08, decay=0.0)

'''
lr：float> = 0.学习率
beta_1：float，0 <beta <1。一般接近1。一阶矩估计的指数衰减率
beta_2：float，0 <beta <1。一般接近1。二阶矩估计的指数衰减率
epsilon：float> = 0,模糊因子。如果None，默认为K.epsilon()。
该参数是非常小的数，其为了防止在实现中除以零
decay：float> = 0,每次更新时学习率下降

'''

```

**sess.run(fetches,   feed_dict=None,    options=None,    run_metadata=None)**：当构建完图后，需要在一个session会话中启动图，第一步是创建一个Session对象。为了取回（Fetch）操作的输出内容, 可以在使用 Session 对象的 run()调用执行图时，传入一些 tensor, 这些 tensor 会取回结果。

## chap0 numpy基本操作

这里持续罗列学习到的 `numpy` 相关操作：
1. 构建数组
```py
np.array                # 构建矩阵
np.asarray              # 转换为array对象
np.zeros((x,y),dtype=)  # 全零矩阵
np.ones((x,y),dtype=)   # 全一矩阵
np.eye((x),dtype=)      # 单位矩阵
np.random.randint(start,end,(x,y)) # 随机矩阵
np.linsapce(start,end,feet,dtype=).reshape([x,y])  # 顺序矩阵

```
2. 数组运算
```py
np.add
np.subtract
np.miltiply
np.divide
np.dot
np.sqrt
np.sum
np.mean
np.exp
np.argmax
```
3. 数组操作
```py
np.expand_dims(x,axis=) # 增维，axis控制轴的前后
np.concatenate(x,axis=) # 拼接，axis控制拼接的维度
```